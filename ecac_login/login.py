"""Login no eCAC via Patchright com client_certificates.

Uso:
    from ecac_login import fazer_login
    p, context, page = fazer_login(cnpj="<CNPJ da empresa>")

Pre-requisitos no .env do projeto chamador:
    CERT_PFX_PATH=meu_certificado.pfx   (nome do arquivo em LoginEcac/Certificados/)
    CERT_PFX_PASSPHRASE=senha-do-pfx    (opcional: lida automaticamente do senhas.json)
    GEMINI_API_KEY=chave-gemini
"""
import json
import os
import threading
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from patchright.sync_api import sync_playwright

from resolvedor_captcha import solve_hcaptcha
from .log_manager import registrar_erro

try:
    from .cert_dialog import selecionar_certificado_no_dialogo as _selecionar_cert_dialog
    _CERT_DIALOG_OK = True
except Exception:
    _CERT_DIALOG_OK = False

ECAC_URL = "http://cav.receita.fazenda.gov.br/ecac/Default.aspx"
CERT_DIR = Path(__file__).parent / "Certificados"

MENSAGEM_ACESSO_BLOQUEADO = (
    "Prezado usuário, o seu acesso foi bloqueado por possuir atributos "
    "que o caracteriza como um acesso automatizado."
)


class AcessoBloqueado(Exception):
    pass


class DispositivosMaximo(Exception):
    pass


MENSAGEM_DISPOSITIVOS_MAXIMOS = (
    "Você atingiu o número máximo de dispositivos conectados simultaneamente com esta conta."
)

class CertificadoInvalido(ValueError):
    """Configuração de certificado malformada — falha local, antes de abrir o navegador."""


# ── Diagnostico do popup de perfil: metadado, nunca conteudo ──────────────────
#
# O bloco `[diag] inputs do formPJ` imprimia cada input do formulario com o
# `value` junto — e um deles e o CNPJ que acabara de ser preenchido. Como o
# runtime do AutoHub captura o stdout, o documento virava dado persistido na
# plataforma.
#
# A defesa fica AQUI, em Python, e nao so no JS: o JS ja devolve a forma
# reduzida, mas quem garante e este filtro de chaves — ele e puro, e por isso
# testavel com sentinela.

CAMPOS_DIAG_INPUT = ("idx", "type", "name", "id", "visible",
                     "preenchido", "parece_alterar", "aciona_captcha")

# Vocabulario FECHADO do resultado do clique via DOM. O valor vem do navegador;
# o que sai no log e sempre um destes, ou "desconhecido".
RESULTADOS_CLIQUE = ("no-form", "no-button", "clicked:visible", "clicked:hidden")


def _diag_inputs(brutos) -> list:
    """So metadado de vocabulario fechado. Nenhum conteudo de campo passa.

    `preenchido` responde a unica pergunta que o diagnostico precisava do
    conteudo — se o campo tem algo dentro — sem carregar o que ha dentro.
    """
    if not isinstance(brutos, list):
        return []
    return [{chave: item.get(chave) for chave in CAMPOS_DIAG_INPUT if chave in item}
            for item in brutos if isinstance(item, dict)]


def _conteudo(page, tentativas: int = 3, espera_ms: int = 250) -> str:
    """HTML da página, ou string vazia se ela estiver navegando.

    `page.content()` levanta quando a navegação está em curso:

        Page.content: Unable to retrieve content because the page is navigating

    Os três usos desta função são **guardas**: procuram a mensagem de acesso
    bloqueado ou a de número máximo de dispositivos. Deixar a exceção subir faz
    a guarda derrubar o login inteiro por não ter conseguido ler o HTML — mais
    frágil do que aquilo que ela protege. E o sintoma não sugere a causa: quem
    lê o erro procura defeito na página, não uma leitura feita cedo demais.

    Os três pontos são justamente os de maior movimento — depois do `goto`,
    depois de apresentar o certificado e depois de submeter o captcha, que por
    definição navega. Algumas centenas de milissegundos depois a mesma leitura
    funciona.

    Devolve `""` quando não conseguiu ler. Não ter lido não é o mesmo que a
    mensagem não estar lá, então a guarda passa — e um falso negativo aqui
    apenas adia a detecção, enquanto a exceção encerrava a run na hora.
    """
    for tentativa in range(tentativas):
        try:
            return page.content()
        except Exception as e:  # noqa: BLE001
            if tentativa == tentativas - 1:
                # Só o tipo da exceção, nunca o texto dela: a política deste
                # repositório é não interpolar objeto de exceção em saída, e a
                # suíte cobra isso. Aqui o tipo já distingue navegação em curso
                # de página fechada, que é a única dúvida real.
                print(f"  -> nao foi possivel ler a pagina ({type(e).__name__})")
                return ""
            try:
                page.wait_for_load_state("domcontentloaded", timeout=5_000)
            except Exception:  # noqa: BLE001
                page.wait_for_timeout(espera_ms)
    return ""


def _resultado_de_clique(valor) -> str:
    """Devolve o valor so se ele for um dos nossos."""
    return valor if valor in RESULTADOS_CLIQUE else "desconhecido"


def _build_auto_select_cert_flag(cert_subject_cn: str | None = None) -> str:
    """Constrói --auto-select-certificate-for-urls filtrando pelo CN do cert selecionado.

    Usada SOMENTE no modo Windows Certificate Store. Com CN definido, o Chrome
    escolhe exatamente o cert correto do store quando há múltiplos instalados.
    Sem CN, usa filtro vazio (primeiro disponível).

    `cert_subject_cn` explícito tem prioridade; quando ausente, mantém-se o
    comportamento atual de ler CERT_SUBJECT_CN do ambiente.
    """
    if cert_subject_cn is None:
        cert_subject_cn = os.getenv("CERT_SUBJECT_CN", "")
    subject_cn = cert_subject_cn.strip()
    filt = {"SUBJECT": {"CN": subject_cn}} if subject_cn else {}
    patterns = [
        "https://[*.]acesso.gov.br",
        "https://[*.]receita.fazenda.gov.br",
        "https://[*.]fazenda.gov.br",
    ]
    entries = json.dumps(
        [{"pattern": p, "filter": filt} for p in patterns],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return f"--auto-select-certificate-for-urls={entries}"

CERT_ORIGINS = [
    "https://certificado.sso.acesso.gov.br",
    "https://sso.acesso.gov.br",
    "https://acesso.gov.br",
    "https://cav.receita.fazenda.gov.br",
    "https://solucoes.receita.fazenda.gov.br",
    "https://sinac.cav.receita.fazenda.gov.br",
    "https://servicos.receita.fazenda.gov.br",
    "https://restituicao.receita.fazenda.gov.br",
    "https://www.restituicao.receita.fazenda.gov.br",
    "https://cte.fazenda.gov.br",
    "https://www.cte.fazenda.gov.br",
    "https://nfe.fazenda.gov.br",
    "https://www.nfe.fazenda.gov.br",
    "https://receita.fazenda.gov.br",
    "https://www.receita.fazenda.gov.br",
    # Domínio novo do portal de serviços da Receita Federal
    "https://servicos.receitafederal.gov.br",
    "https://receitafederal.gov.br",
    "https://www.receitafederal.gov.br",
]


def _configurar_download(user_data_dir: str) -> None:
    """Configura o diretório de download do perfil Chrome para a pasta Downloads do usuário."""
    downloads_dir = str(Path.home() / "Downloads")
    prefs_dir = Path(user_data_dir) / "Default"
    prefs_dir.mkdir(parents=True, exist_ok=True)
    prefs_file = prefs_dir / "Preferences"

    try:
        prefs = json.loads(prefs_file.read_text(encoding="utf-8")) if prefs_file.exists() else {}
    except Exception:
        prefs = {}

    prefs.setdefault("download", {})
    prefs["download"]["default_directory"] = downloads_dir
    prefs["download"]["prompt_for_download"] = False
    prefs["download"]["directory_upgrade"] = True
    prefs.setdefault("savefile", {})
    prefs["savefile"]["default_directory"] = downloads_dir
    # Faz o Chrome tratar PDFs como download em vez de abrir no viewer interno
    prefs.setdefault("plugins", {})
    prefs["plugins"]["always_open_pdf_externally"] = True

    prefs_file.write_text(json.dumps(prefs), encoding="utf-8")
    print("[download] Diretorio de download configurado.")


def _build_client_certificates(cert_pfx_path, cert_pfx_passphrase):
    """Monta `client_certificates` a partir do PFX recebido por argumento.

    Uma entrada por origem: `client_certificates` casa por ORIGEM EXATA, sem
    wildcard. A passphrase é repassada como veio — a API aceita `str | None`, e
    exigir senha não vazia inventaria uma regra que o contrato não tem.

    Nota histórica: esta função devolvia `None` incondicionalmente, com a
    justificativa de que `client_certificates` falharia com a cadeia ICP-Brasil
    (SSL alert 40). Essa hipótese foi REFUTADA POR MEDIÇÃO: o probe DEV
    `AUT-0008` completou o handshake mTLS e chegou à home autenticada do eCAC
    por este exato caminho, com Patchright 1.60.1.
    """
    return [
        {"origin": origin,
         "pfxPath": str(cert_pfx_path),
         "passphrase": cert_pfx_passphrase}
        for origin in CERT_ORIGINS
    ]


def _montar_launch_kwargs(user_data_dir: str, *,
                          cert_pfx_path=None,
                          cert_pfx_passphrase=None,
                          cert_subject_cn: str | None = None) -> dict:
    """Monta os kwargs de lançamento do Chrome. Função PURA.

    Não abre navegador, não toca filesystem e não lê segredo — existe para que a
    configuração de certificado seja testável sem Chrome.

    Dois modos, mutuamente exclusivos. Quem escolhe é a PRESENÇA de
    `cert_pfx_path`, nunca a senha: deixar a passphrase decidir faria um pedido
    explícito de PFX virar modo Store em silêncio.

    MODO PFX (`cert_pfx_path` informado)
        `client_certificates` montado a partir do argumento e a flag
        `--auto-select-certificate-for-urls` AUSENTE. `cert_subject_cn`,
        `CERT_SUBJECT_CN` do ambiente e `cert_serial` residual não reativam o
        Windows Certificate Store.
        É a mesma semântica de entrega e seleção de certificado validada no
        Probe 1: PFX via `client_certificates` e ausência de auto-select do
        Windows Store.

    MODO STORE (`cert_pfx_path` ausente)
        Comportamento atual do desktop, preservado: sem `client_certificates` e
        com a flag de auto-seleção.
    """
    args = ["--start-maximized", "--remote-debugging-port=9222"]
    kwargs = dict(
        user_data_dir=user_data_dir,
        channel="chrome",
        headless=False,
        no_viewport=True,
        ignore_https_errors=True,
        accept_downloads=True,
        args=args,
    )

    if cert_pfx_path is None:
        args.append(_build_auto_select_cert_flag(cert_subject_cn))
        return kwargs

    if not str(cert_pfx_path).strip():
        # Pedido explícito de PFX com caminho vazio é erro de configuração.
        # Cair para o Store aqui seria trocar o mecanismo em silêncio.
        raise CertificadoInvalido(
            "cert_pfx_path foi informado vazio; forneca um caminho valido "
            "ou omita o parametro para usar o Windows Certificate Store.")

    kwargs["client_certificates"] = _build_client_certificates(
        cert_pfx_path, cert_pfx_passphrase)
    return kwargs


def _try_solve_captcha(page, etapa: str, max_attempts: int = 3, metrics_fn=None) -> bool:
    print(f"[{etapa}] Verificando hCaptcha (ate {max_attempts} tentativas)...")
    for tentativa in range(1, max_attempts + 1):
        try:
            resultado = solve_hcaptcha(page)
            if resultado:
                print(f"[{etapa}] tentativa {tentativa}/{max_attempts}: OK (resolvido ou ausente).")
                return True
            print(f"[{etapa}] tentativa {tentativa}/{max_attempts}: solver retornou False.")
        except Exception as e:
            print(f"[{etapa}] tentativa {tentativa}/{max_attempts}: {type(e).__name__}")
        page.wait_for_timeout(2_000)
    return False


def abrir_browser_com_certificado(project_dir: Path | str = None):
    """Abre o Chrome com o certificado digital configurado e retorna (p, context, page).

    Não faz login no eCAC — apenas abre o navegador com os client_certificates
    carregados para autenticação direta no portal de serviços RF.

    Args:
        project_dir: Diretório do projeto chamador. Usado para o perfil Chrome e .env.

    Returns:
        Tupla (p, context, page) — navegador aberto, sem navegação inicial.
    """
    if project_dir is None:
        project_dir = Path.cwd()
    project_dir = Path(project_dir)

    load_dotenv(dotenv_path=project_dir / ".env", override=True)

    user_data_dir = str(project_dir / "chrome_debug_profile")
    os.makedirs(user_data_dir, exist_ok=True)

    _configurar_download(user_data_dir)
    # Sem parâmetros de certificado: modo Windows Certificate Store, como antes.
    launch_kwargs = _montar_launch_kwargs(user_data_dir)

    p = sync_playwright().start()
    print("Lancando Chrome (certificado carregado)...")
    context = p.chromium.launch_persistent_context(**launch_kwargs)
    print("Chrome lancado.")

    page = context.pages[0] if context.pages else context.new_page()
    print("Pagina obtida.")
    return p, context, page


def main(cnpj: str, project_dir: Path | str = None, metrics=None, policy_ok: bool = True,
         cert_serial: str = "", *,
         cert_pfx_path: str | None = None,
         cert_pfx_passphrase: str | None = None,
         cert_subject_cn: str | None = None):
    """Realiza o login no eCAC e retorna (playwright, context, page) autenticados.

    Duas formas de apresentar o certificado, mutuamente exclusivas — ver
    `_montar_launch_kwargs` para a regra de precedencia:

    A) PFX explicito (`cert_pfx_path`) — o arquivo e entregue ao Chrome via
       `client_certificates` e a auto-selecao do Windows Certificate Store fica
       DESLIGADA. E o caminho para agente desassistido: nao usa store, certutil,
       UAC nem policy de registro.

    B) Windows Certificate Store (padrao, sem `cert_pfx_path`) — comportamento
       atual do desktop, inalterado.

    Args:
        cnpj: CNPJ da empresa (14 digitos, sem formatacao).
        project_dir: Diretorio do projeto chamador. Usado para salvar o perfil do Chrome
                     e screenshots de debug. Padrao: diretorio de trabalho atual.
        metrics: Coletor opcional de metricas de captcha.
        policy_ok: True se a policy de auto-selecao do registro esta ativa. False
                   ativa o fallback pywinauto — relevante somente no modo B.
        cert_serial: Serial do cert escolhido, usado pelo fallback pywinauto.
                     Sem efeito no modo A.
        cert_pfx_path: Caminho do .pfx (modo A). A PRESENCA deste argumento e o
                       que seleciona o modo PFX.
        cert_pfx_passphrase: Senha do .pfx (modo A). Repassada como veio.
        cert_subject_cn: CN do certificado no store (modo B). Quando ausente,
                         mantem-se a leitura de CERT_SUBJECT_CN do ambiente.

    Returns:
        Tupla (p, context, page) em caso de sucesso, ou None em caso de falha.
    """
    if project_dir is None:
        project_dir = Path.cwd()
    project_dir = Path(project_dir)

    load_dotenv(dotenv_path=project_dir / ".env", override=True)

    user_data_dir = str(project_dir / "chrome_debug_profile")
    os.makedirs(user_data_dir, exist_ok=True)

    _configurar_download(user_data_dir)
    launch_kwargs = _montar_launch_kwargs(
        user_data_dir,
        cert_pfx_path=cert_pfx_path,
        cert_pfx_passphrase=cert_pfx_passphrase,
        cert_subject_cn=cert_subject_cn,
    )
    # Só o MODO, nunca o valor: caminho do .pfx, senha, CN e serial não vão para o log.
    print("[cert] Modo PFX explicito." if cert_pfx_path is not None
          else "[cert] Modo Windows Certificate Store.")

    p = sync_playwright().start()
    print("Lancando Chrome...")
    context = p.chromium.launch_persistent_context(**launch_kwargs)
    print("Chrome lancado.")

    page = context.pages[0] if context.pages else context.new_page()
    print("Pagina obtida.")

    # Quem LANCA fecha. Ponto unico: antes, cada caminho de falha decidia por si
    # se fechava, e alguns nao fechavam — o Chrome ficava vivo segurando o
    # diretorio de perfil, e quem tentasse remover o temporario depois batia em
    # PermissionError no Windows.
    try:
        ok = garantir_acesso_ecac(page, cnpj, metrics=metrics,
                                  policy_ok=policy_ok, cert_serial=cert_serial)
    except BaseException:
        encerrar_sessao(p, context)
        raise
    if not ok:
        encerrar_sessao(p, context)
        return None
    return p, context, page


def encerrar_sessao(p=None, context=None) -> None:
    """Fecha contexto e para o Playwright. IDEMPOTENTE e sem levantar.

    Chamar duas vezes nao pode virar erro: o teardown da execucao e o caminho
    de falha de quem lancou podem alcancar a mesma sessao.
    """
    try:
        if context is not None:
            context.close()
    except Exception:  # noqa: BLE001, S110 — fechar duas vezes nao e erro
        pass
    try:
        if p is not None:
            p.stop()
    except Exception:  # noqa: BLE001, S110
        pass


def garantir_acesso_ecac(page, cnpj: str, *, metrics=None,
                         policy_ok: bool = True, cert_serial: str = "") -> bool:
    """Garante eCAC autenticado com o perfil PJ do CNPJ, numa sessao EXISTENTE.

    Nao lanca navegador, nao cria contexto e NAO FECHA NADA: a sessao pertence a
    quem a criou. Existe porque uma execucao que passa pelo Servicos RF e depois
    pelo eCAC ja tem um Chrome autenticado — lancar outro descarta o certificado
    ja apresentado e a autenticacao ja obtida.

    Reutilizar NAO e assumir: o fluxo verifica autenticacao e perfil, e so
    autentica ou troca de perfil quando e preciso.

    True quando o eCAC esta autenticado e o perfil ativo e o CNPJ pedido.
    False quando nao foi possivel garantir isso. `AcessoBloqueado` continua
    subindo para quem decide reiniciar.
    """

    def _captcha_fn(chamadas: int, resolvido: bool, rodadas: int) -> None:
        if metrics:
            metrics.registrar_captcha(chamadas, resolvido, rodadas)

    def _ja_logado():
        return "cav.receita.fazenda.gov.br/ecac" in page.url and "autenticacao" not in page.url

    print("Abrindo o eCAC ...")
    try:
        page.goto(ECAC_URL, wait_until="commit", timeout=30_000)
        print("  -> pagina inicial carregada.")
    except Exception as e:
        print(f"  -> erro no goto: {type(e).__name__}")
        return False

    page.wait_for_timeout(1_500)
    print("Verificando bloqueio de acesso automatizado...")
    if MENSAGEM_ACESSO_BLOQUEADO in _conteudo(page):
        registrar_erro("Login: acesso bloqueado — pagina exibiu mensagem de acesso automatizado.")
        print("  -> [BLOQUEADO] Acesso bloqueado. Sinalizando reinicio...")
        raise AcessoBloqueado()

    sessao_ativa = False
    if _ja_logado():
        try:
            page.locator("#btnPerfil").first.wait_for(state="visible", timeout=5_000)
            print("  -> Sessao ativa detectada. Pulando etapas de autenticacao.")
            sessao_ativa = True
        except Exception:
            print("  -> URL indica eCAC mas dashboard nao carregou. Prosseguindo com login normal.")

    if not sessao_ativa:
        print("Verificando se ha link 'Voltar para a pagina de login'...")
        try:
            voltar_link = page.locator('a.ui-link[href="/autenticacao"]').first
            if voltar_link.is_visible(timeout=3_000):
                print("  -> link encontrado. Clicando...")
                voltar_link.click()
                page.wait_for_load_state("domcontentloaded", timeout=20_000)
                print("  -> retornou para a pagina de login.")
        except Exception:
            pass

        print("Clicando em 'Entrar com gov.br'...")
        gov_btn = page.locator('xpath=//*[@id="login-dados-certificado"]/p[2]/input').first
        try:
            gov_btn.wait_for(state="visible", timeout=15_000)
            gov_btn.click()
        except Exception as e:
            print(f"  -> botao nao encontrado: {type(e).__name__}")
            return False

        print("  -> clicado.")

        if not _try_solve_captcha(page, "captcha-pos-govbr", metrics_fn=_captcha_fn):
            if _ja_logado():
                print("  -> captcha falhou mas pagina ja esta logada. Continuando.")
            else:
                registrar_erro("Login: hCaptcha nao resolvido apos 3 tentativas (etapa gov.br).")
                print("[captcha] 3 tentativas falharam. Abortando.")
                return False

    cert_selectors = [
        "#login-certificate",
        "a:has-text('Seu certificado digital')",
        "button:has-text('Seu certificado digital')",
        "text=Seu certificado digital",
    ]

    def _clicar_certificado() -> bool:
        print("Procurando botao 'Seu certificado digital'...")
        for i, sel in enumerate(cert_selectors):
            try:
                loc = page.locator(sel).first
                loc.wait_for(state="visible", timeout=20_000 if i == 0 else 2_000)
                print(f"  -> match com: {sel}")
                loc.click()
                return True
            except Exception:
                continue
        print("  -> botao 'Seu certificado digital' nao encontrado.")
        return False

    if not sessao_ativa:
        MAX_TENTATIVAS_CERT = 3
        for tentativa_cert in range(1, MAX_TENTATIVAS_CERT + 1):
            print(f"[cert] Tentativa {tentativa_cert}/{MAX_TENTATIVAS_CERT}...")

            if _ja_logado():
                print("  -> ja logado no inicio da tentativa. Saindo do loop de cert.")
                break

            if not _clicar_certificado():
                if _ja_logado():
                    print("  -> botao nao encontrado mas pagina ja esta logada. Continuando.")
                    break
                registrar_erro("Login: botao 'Seu certificado digital' nao encontrado.")
                print("[cert] Botao nao encontrado. Abortando.")
                return False

            # Fallback: se a policy do registro nao funcionou, pywinauto seleciona
            # o certificado na janela nativa que o Chrome exibir.
            if not policy_ok and _CERT_DIALOG_OK:
                _cn = os.getenv("CERT_SUBJECT_CN", "").strip()
                threading.Thread(
                    target=_selecionar_cert_dialog,
                    args=(_cn, cert_serial),
                    kwargs={"timeout": 90.0},
                    daemon=True,
                ).start()
            elif tentativa_cert == 1:
                print("[cert] Policy de auto-selecao ativa — Chrome escolhe o certificado sozinho.")

            print("  -> clicado. Aguardando recarregar...")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=20_000)
            except Exception:
                pass
            page.wait_for_timeout(2_000)
            print("  -> certificado apresentado; navegacao seguiu.")

            if MENSAGEM_DISPOSITIVOS_MAXIMOS in _conteudo(page):
                registrar_erro("Login: numero maximo de dispositivos conectados atingido.")
                print("  -> [DISPOSITIVOS] Numero maximo de dispositivos atingido. Fechando navegador...")
                raise DispositivosMaximo()

            if _ja_logado():
                print("  -> login realizado sem captcha.")
                break

            print("  -> verificando captcha pos-certificado...")
            if not _try_solve_captcha(page, f"captcha-pos-cert-t{tentativa_cert}", metrics_fn=_captcha_fn):
                print(f"[captcha] tentativa {tentativa_cert}: falhou ao resolver captcha.")

            if MENSAGEM_DISPOSITIVOS_MAXIMOS in _conteudo(page):
                registrar_erro("Login: numero maximo de dispositivos conectados atingido.")
                print("  -> [DISPOSITIVOS] Numero maximo de dispositivos atingido. Fechando navegador...")
                raise DispositivosMaximo()

            if _ja_logado():
                print("  -> login realizado apos captcha.")
                break

            if tentativa_cert < MAX_TENTATIVAS_CERT:
                print(f"  -> login nao concluido. Recarregando e tentando novamente...")
                page.reload(wait_until="domcontentloaded")
                page.wait_for_timeout(2_000)
            else:
                if _ja_logado():
                    print("  -> ultima tentativa mas pagina ja esta logada. Continuando.")
                    break
                registrar_erro("Login: nao concluido apos todas as tentativas com certificado digital.")
                print("[cert] Login nao concluido apos todas as tentativas. Abortando.")
                return False

        print("Captcha pos-certificado tratado.")
        print("  -> captcha tratado; navegacao seguiu.")

        print("Aguardando redirecionamento final para cav.receita.fazenda.gov.br/ecac (ate 90s)...")
        try:
            page.wait_for_url(
                lambda u: "cav.receita.fazenda.gov.br/ecac" in u and "autenticacao" not in u,
                timeout=90_000,
            )
            print("  -> redirecionamento final concluido.")
        except Exception as e:
            registrar_erro("Login: redirecionamento final para o eCAC nao ocorreu.")
            print(f"  -> nao chegou no eCAC: {type(e).__name__}")
            try:
                shot = str(project_dir / "_debug_pos_cert.png")
                page.screenshot(path=shot, full_page=True)
                print("     screenshot de debug gravado.")
            except Exception:
                pass
            return False

    print("Aguardando dashboard do eCAC carregar (#btnPerfil, ate 60s)...")
    try:
        page.locator("#btnPerfil").first.wait_for(state="visible", timeout=60_000)
    except Exception as e:
        registrar_erro("Login: dashboard do eCAC nao carregou (#btnPerfil ausente).")
        print(f"  -> erro aguardando dashboard: {type(e).__name__}")
        try:
            shot = str(project_dir / "_debug_dashboard.png")
            page.screenshot(path=shot, full_page=True)
            print("     screenshot de debug gravado.")
        except Exception:
            pass
        return False

    page.wait_for_timeout(3_000)

    try:
        if page.locator('#dialog-bloqueio-ativo-caixapostal').first.is_visible(timeout=2_000):
            print("  -> popup 'mensagens importantes' detectado. Clicando em 'Ir para a Caixa Postal'...")
            page.get_by_role("button", name="Ir para a Caixa Postal").first.click(timeout=5_000)
            page.wait_for_load_state("domcontentloaded", timeout=30_000)
            return True
    except Exception:
        pass

    print("Clicando em 'Alterar perfil de acesso'...")
    page.locator("#btnPerfil").first.click()

    print("Aguardando popup carregar (formPJ no DOM)...")
    try:
        page.locator("#formPJ").first.wait_for(state="attached", timeout=15_000)
    except Exception:
        print("  -> #formPJ nao aparece. Abortando.")
        return False

    print("Ativando aba 'Pessoa Juridica'...")
    pj_tab_selectors = [
        "[onclick*='formPJ']",
        "[href='#formPJ']",
        "a:has-text('Procurador de pessoa jur')",
        "a:has-text('Pessoa Jur')",
        "label:has-text('Jur')",
    ]
    tab_clicked = False
    for sel in pj_tab_selectors:
        try:
            loc = page.locator(sel).first
            if loc.is_visible(timeout=1_500):
                loc.click()
                print(f"  -> aba ativada via: {sel}")
                tab_clicked = True
                break
        except Exception:
            continue
    if not tab_clicked:
        print("  -> nenhum seletor de aba bateu (talvez ja esteja ativa).")

    print("Aguardando #txtNIPapel2 ficar visivel...")
    nip_input = page.locator("#txtNIPapel2").first
    try:
        nip_input.wait_for(state="visible", timeout=10_000)
    except Exception:
        print("  -> input nao ficou visivel; vai tentar fallback via JS.")

    print("Preenchendo identificador do perfil PJ em #txtNIPapel2...")
    try:
        nip_input.fill(cnpj)
    except Exception:
        print("  -> fill falhou, injetando via JS...")
        page.evaluate(
            "(v) => { const i = document.getElementById('txtNIPapel2');"
            " if (i) { i.value = v;"
            " i.dispatchEvent(new Event('input', {bubbles:true}));"
            " i.dispatchEvent(new Event('change', {bubbles:true})); } }",
            cnpj,
        )

    page.wait_for_timeout(500)

    print("Aguardando funcao validaCaptcha ficar disponivel...")
    try:
        page.wait_for_function("typeof validaCaptcha !== 'undefined'", timeout=15_000)
        print("  -> validaCaptcha pronta.")
    except Exception:
        print("  -> validaCaptcha nao apareceu no window. Vai tentar mesmo assim.")

    try:
        inputs_info = page.evaluate(
            """() => {
                const f = document.getElementById('formPJ');
                if (!f) return null;
                return Array.from(f.querySelectorAll('input')).map((i, idx) => {
                    const onclick = i.getAttribute('onclick') || '';
                    return {
                        idx, type: i.type, name: i.name, id: i.id,
                        visible: i.offsetParent !== null,
                        preenchido: !!(i.value && i.value.length),
                        parece_alterar: (i.type === 'submit' || i.type === 'button')
                                        && i.value === 'Alterar',
                        aciona_captcha: onclick.includes('validaCaptcha'),
                    };
                });
            }"""
        )
        print(f"[diag] inputs do formPJ: {_diag_inputs(inputs_info)}")
    except Exception as e:
        print(f"[diag] inputs do formPJ: falhou ({type(e).__name__})")

    ERROS_FATAIS = [
        "CNPJ deve ser informado com todos os 14 dígitos.",
        "Não existe procuração eletrônica para o detentor",
        "CNPJ informado inválido.",
        "A procuração eletrônica cadastrada para o detentor",
    ]
    ERRO_ACESSO_AUTOMATIZADO = (
        "Não foi possível alterar o perfil de acesso. A execução possui atributos "
        "que caracteriza acesso automatizado. Tente novamente mais tarde"
    )

    def _detectar_erro_alterar() -> str | None:
        for msg in ERROS_FATAIS + [ERRO_ACESSO_AUTOMATIZADO]:
            try:
                if page.locator(f'text={msg}').first.is_visible(timeout=1_500):
                    return msg
            except Exception:
                continue
        return False

    def _fechar_popup_e_sair():
        print("  -> Fechando popup de perfil...")
        try:
            page.locator('xpath=/html/body/div[11]/div[1]/a/span').first.click(timeout=5_000)
        except Exception:
            pass
        page.wait_for_timeout(1_000)
        print("  -> Clicando em 'Sair com Seguranca'...")
        try:
            page.locator('xpath=//*[@id="sairSeguranca"]/span').first.click(timeout=5_000)
        except Exception:
            pass
        page.wait_for_timeout(5_000)

    def _clicar_alterar():
        submit_btn = page.locator('xpath=//*[@id="formPJ"]/input[4]').first
        try:
            submit_btn.click(timeout=5_000)
            print("  -> clicado.")
            return
        except Exception as e:
            print(f"  -> click normal falhou ({type(e).__name__}). Tentando force-click...")
        try:
            submit_btn.click(force=True, timeout=3_000)
            print("  -> force-click ok.")
            return
        except Exception as e2:
            print(f"  -> force-click falhou ({type(e2).__name__}). Tentando DOM .click()...")
        try:
            result = page.evaluate(
                """() => {
                    const f = document.getElementById('formPJ');
                    if (!f) return 'no-form';
                    const candidates = Array.from(f.querySelectorAll('input')).filter(
                        i => i.value === 'Alterar' || (i.getAttribute('onclick')||'').includes('validaCaptcha')
                    );
                    if (candidates.length === 0) return 'no-button';
                    const visible = candidates.find(b => b.offsetParent !== null) || candidates[0];
                    visible.click();
                    return 'clicked:' + (visible.offsetParent !== null ? 'visible' : 'hidden');
                }"""
            )
            print(f"  -> DOM click resultado: {_resultado_de_clique(result)}")
        except Exception as e3:
            print(f"  -> falhou tudo: {type(e3).__name__}")

    MAX_TENTATIVAS_ALTERAR = 5
    for tentativa_alterar in range(1, MAX_TENTATIVAS_ALTERAR + 1):
        print(f"Clicando no botao 'Alterar' (formPJ) — tentativa {tentativa_alterar}...")
        _clicar_alterar()

        page.wait_for_timeout(2_500)

        erro = _detectar_erro_alterar()

        if erro == ERRO_ACESSO_AUTOMATIZADO:
            print(f"  -> [acesso automatizado] detectado. Aguardando 10s e tentando novamente...")
            page.wait_for_timeout(10_000)
            if tentativa_alterar == MAX_TENTATIVAS_ALTERAR:
                registrar_erro("Acesso automatizado detectado ao alterar o perfil: "
                               f"limite de {MAX_TENTATIVAS_ALTERAR} tentativas atingido.")
                print("  -> Limite de tentativas atingido para erro de acesso automatizado. Abortando.")
                _fechar_popup_e_sair()
                return False
            continue

        if erro:
            registrar_erro(erro)
            _fechar_popup_e_sair()
            return False

        print("Aguardando popup fechar (ate 20s)...")
        try:
            page.locator("#txtNIPapel2").first.wait_for(state="hidden", timeout=20_000)
            print("  -> popup fechou.")
        except Exception:
            print("  -> popup nao fechou no tempo esperado, seguindo mesmo assim.")
        break

    try:
        page.wait_for_load_state("domcontentloaded", timeout=15_000)
    except Exception:
        pass
    print("  -> perfil de acesso alterado.")
    print("Concluido.")
    return True
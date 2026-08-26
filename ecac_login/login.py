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
import re
import threading
import time
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


# ── Clique com prova ──────────────────────────────────────────────────────────
#
# `locator.click()` voltar sem excecao significa que o evento foi DESPACHADO:
# o elemento estava visivel, estavel e recebendo cliques, e o mouse desceu e
# subiu em cima dele. Nao significa que alguem atendeu do outro lado.
#
# O caso comum e clicar antes de a pagina terminar de carregar: o botao ja esta
# desenhado, mas o script que responde por ele ainda nao rodou. O clique cai no
# vazio, o log diz "clicado", e o erro so aparece la na frente — procurando uma
# tela que nunca chegou.
CLIQUES_GOVBR = 3
ESPERA_PROVA_MS = 6_000     # janela para a pagina reagir a um clique
PASSO_PROVA_MS = 250


def _pagina_pronta(page, timeout_ms: int = 10_000) -> bool:
    """True quando o documento terminou de carregar.

    Pelo `document.readyState`, que e do DOM: variaveis definidas PELA pagina
    nao servem aqui, porque o patchright avalia num mundo isolado e elas
    responderiam "undefined" mesmo definidas.
    """
    limite = time.monotonic() + timeout_ms / 1000.0
    while True:
        try:
            if page.is_closed():
                return False
            if page.evaluate("() => document.readyState") == "complete":
                return True
        except Exception:
            # Contexto morre no meio de uma navegacao: e sinal de pagina viva.
            pass
        if time.monotonic() >= limite:
            return False
        try:
            page.wait_for_timeout(200)
        except Exception:
            return False


def _desafio_hcaptcha_visivel(page) -> bool:
    """True quando o DESAFIO do hCaptcha esta na tela — nao o widget invisivel.

    A distincao ja custou caro. A pagina de login do e-CAC NASCE com um iframe
    do hCaptcha embutido: o widget invisivel do `#hcaptcha-govbr`, com
    `frame=checkbox-invisible` na URL. Ele esta la desde o primeiro byte, antes
    de qualquer clique.

    Contar esse iframe como "o captcha apareceu" faz qualquer prova de reacao
    dar positivo ANTES do clique — e foi exatamente isso que aconteceu: o
    "Entrar com gov.br" deixou de ser clicado, porque a prova ja dizia que a
    pagina havia reagido.

    O que so existe DEPOIS de `hcaptcha.execute()` e o desafio VISIVEL: ate la
    ele fica num container com visibility:hidden e top:-10000px.
    """
    for sel in ("iframe[src*='hcaptcha'][src*='frame=challenge']",
                "iframe[title*='hCaptcha' i]"):
        try:
            if page.locator(sel).first.is_visible(timeout=200):
                return True
        except Exception:
            continue
    return False


# ── Sonda do mundo da pagina ──────────────────────────────────────────────────
#
# O patchright avalia num mundo ISOLADO: enxerga o DOM, mas nao as variaveis que
# a pagina definiu. `page.evaluate("typeof hcaptcha")` responde "undefined" com
# o script perfeitamente carregado — medido.
#
# `add_script_tag` insere um <script> de verdade no documento, e esse roda no
# mundo da PAGINA. Ele nao devolve valor para ca, entao escreve a resposta num
# atributo: o DOM e o terreno que os dois mundos compartilham.
ATRIBUTO_SONDA = "data-ecac-sonda"
ESPERA_HANDLER_MS = 15_000
_NOME_SEGURO = re.compile(r"^[A-Za-z_$][\w$]*$")


def _tipos_na_pagina(page, nomes: tuple) -> dict:
    """`typeof <nome>` para cada nome, medido DENTRO da pagina.

    Devolve {} quando a sonda nao pode ser feita (CSP bloqueando script inline,
    navegacao em curso, guia fechada). Vazio e "nao sei", nunca "nao existe".
    """
    nomes = tuple(n for n in nomes if _NOME_SEGURO.match(n or ""))
    if not nomes:
        return {}
    partes = ",".join(f"'{n}:'+(typeof {n})" for n in nomes)
    tag = None
    try:
        tag = page.add_script_tag(content=(
            f"document.documentElement.setAttribute("
            f"'{ATRIBUTO_SONDA}', [{partes}].join('|'));"))
        bruto = page.evaluate(
            f"() => document.documentElement.getAttribute('{ATRIBUTO_SONDA}')")
    except Exception:
        bruto = None
    for limpar in (lambda: tag.evaluate("el => el.remove()") if tag else None,
                   lambda: page.evaluate(
                       f"() => document.documentElement.removeAttribute("
                       f"'{ATRIBUTO_SONDA}')")):
        try:
            limpar()
        except Exception:
            pass
    if not bruto:
        return {}
    achados = {}
    for item in bruto.split("|"):
        nome, _, tipo = item.partition(":")
        achados[nome] = tipo
    return achados


def _pronto_para_govbr(page, timeout_ms: int = None) -> bool:
    """Espera existir QUEM ATENDA o clique do 'Entrar com gov.br'.

    O botao e `<input type="image" onclick="validarHcaptcha('govBr')">`, e essa
    funcao usa `$(...)` e `hcaptcha.execute(...)`. O hcaptcha vem de um
    `<script async defer>` do proprio hcaptcha.com.

    Ou seja: existe uma janela real em que o botao ja esta desenhado, o clique e
    despachado, e a funcao estoura no meio por falta do `hcaptcha`. Nada
    aparece — nem erro nosso, nem mudanca na tela. E o "diz que clicou mas nao
    clicou".

    Nunca impede o clique: sem resposta da sonda ou com o prazo esgotado,
    devolve o controle assim mesmo e deixa a prova de reacao decidir.
    """
    timeout_ms = ESPERA_HANDLER_MS if timeout_ms is None else timeout_ms
    alvos = ("validarHcaptcha", "hcaptcha", "jQuery")
    limite = time.monotonic() + timeout_ms / 1000.0
    avisou = False
    while True:
        try:
            if page.is_closed():
                return False
        except Exception:
            return False
        tipos = _tipos_na_pagina(page, alvos)
        if not tipos:
            print("  -> nao deu para sondar a pagina; seguindo para o clique.")
            return True
        faltando = [n for n in alvos if tipos.get(n) in (None, "undefined")]
        if not faltando:
            if avisou:
                print("  -> a pagina ja tem quem atenda o clique.")
            return True
        if not avisou:
            avisou = True
            print(f"  -> a pagina ainda nao carregou {', '.join(faltando)}; "
                  "esperando antes de clicar.")
        if time.monotonic() >= limite:
            print(f"  -> [AVISO] {', '.join(faltando)} nao apareceu(ram) em "
                  f"{timeout_ms / 1000:.0f}s; clicando assim mesmo.")
            return True
        try:
            page.wait_for_timeout(PASSO_PROVA_MS)
        except Exception:
            return False


def _esperar_reacao(prova, espera_ms: int = None) -> bool:
    """Poll em `prova` ate a janela fechar. Excecao dela conta como 'ainda nao'.

    O prazo e lido AQUI, e nao no valor padrao da assinatura: assim continua
    sendo o do modulo, que os testes ajustam.
    """
    espera_ms = ESPERA_PROVA_MS if espera_ms is None else espera_ms
    limite = time.monotonic() + espera_ms / 1000.0
    while True:
        try:
            if prova():
                return True
        except Exception:
            pass
        if time.monotonic() >= limite:
            return False
        time.sleep(PASSO_PROVA_MS / 1000.0)


# O "Entrar com gov.br" e um <input type="image">, nao um <button>. Os
# seletores vao do mais especifico ao mais generico: o onclick nomeia o handler
# e e o que ha de mais estavel; o caminho absoluto fica por ultimo, porque
# depende da ordem dos <p> dentro do bloco.
SEL_GOVBR = (
    '#login-dados-certificado input[onclick*="validarHcaptcha"]',
    '#frmLoginCert input[type="image"]',
    'input[type="image"][alt*="Gov" i]',
    'xpath=//*[@id="login-dados-certificado"]/p[2]/input',
)


def _achar_govbr(page, timeout_ms: int = 1_000):
    """(locator, seletor css) do primeiro VISIVEL, ou (None, "").

    O seletor volta junto porque uma das vias de clique precisa dele em CSS
    para injetar na pagina; caminho absoluto nao serve la, e por isso volta "".
    """
    for sel in SEL_GOVBR:
        try:
            loc = page.locator(sel).first
            if loc.count() and loc.is_visible(timeout=timeout_ms):
                return loc, ("" if sel.startswith("xpath=") else sel)
        except Exception:
            continue
    return None, ""


def _prova_govbr(page, url_antes: str):
    """Devolve a funcao que responde se o clique no gov.br foi atendido.

    Cada item e uma MUDANCA, nunca um estado que a pagina ja tinha ao carregar
    — foi essa confusao que fez o clique ser pulado por inteiro. O widget
    invisivel do hCaptcha nasce com a pagina e por isso nao conta; o desafio
    VISIVEL conta, porque so aparece depois de `hcaptcha.execute()`.
    """
    def _reagiu() -> bool:
        if page.is_closed():
            return False
        if page.url != url_antes:
            return True          # o formulario foi enviado
        if _desafio_hcaptcha_visivel(page):
            return True          # o hCaptcha pediu a vez
        for sel in ("#login-certificate", "text=Seu certificado digital"):
            try:
                if page.locator(sel).first.is_visible(timeout=200):
                    return True
            except Exception:
                continue
        # Ultimo recurso: o proprio botao saiu da tela.
        try:
            return _achar_govbr(page, timeout_ms=200)[0] is None
        except Exception:
            return True

    return _reagiu


def _clicar_por_todas_as_vias(page, localizar, seletor_css: str,
                              descricao: str, via_inicial: int = 0) -> str:
    """Clica pela primeira via que nao levantar. Devolve o nome da via, ou "".

    As vias vao da mais fiel a mais insistente, e cada uma cobre uma falha
    diferente da anterior:

      1. clique real       — mouse de verdade; e o que o portal espera.
      2. evento de clique  — despacha o evento NO elemento, sem mouse. Passa
                             por cima de qualquer coisa que esteja cobrindo.
      3. clique na pagina  — um <script> injetado chama `.click()` do lado de
                             LA. E o unico jeito de o clique nascer no mundo da
                             pagina; util quando o handler inline depende de
                             `window.event`, que o mundo isolado nao alimenta.
      4. clique forcado    — por ultimo de proposito, e nao primeiro como
                             parecia natural. `force=True` pula as checagens do
                             Playwright e clica NAS COORDENADAS: com um overlay
                             por cima, o clique acerta o overlay, nao volta
                             erro nenhum, e nada acontece. Medido. E um clique
                             em falso com cara de sucesso — o oposto do que se
                             quer numa via de reserva.

    `via_inicial` faz a repeticao comecar por uma via diferente: se a primeira
    ja foi despachada e nada aconteceu, repeti-la igual tende a dar no mesmo.
    """
    loc = localizar()
    if loc is None:
        return ""
    try:
        loc.scroll_into_view_if_needed(timeout=2_000)
    except Exception:
        pass

    vias = [
        ("clique real", lambda: loc.click(timeout=5_000)),
        ("evento de clique", lambda: loc.dispatch_event("click")),
    ]
    if seletor_css:
        alvo = seletor_css.replace("\\", "\\\\").replace("'", "\\'")
        vias.append(("clique dentro da pagina", lambda: page.add_script_tag(
            content=f"document.querySelector('{alvo}').click();")))
    vias.append(("clique forcado", lambda: loc.click(timeout=5_000, force=True)))

    for indice in range(len(vias)):
        nome, acao = vias[(via_inicial + indice) % len(vias)]
        try:
            acao()
            return nome
        except Exception as e:
            print(f"    -> {descricao} por {nome}: {type(e).__name__}")
    return ""


def _clicar_ate_reagir(page, localizar, seletor_css, prova, descricao: str,
                       tentativas: int = None, espera_ms: int = None) -> bool:
    """Clica ate `prova()` confirmar que a pagina reagiu. False se nunca reagiu.

    `localizar()` devolve o locator na HORA do clique, e nao antes: entre a
    busca e o clique a tela pode ter sido remontada.

    A primeira tentativa CLICA, sem consultar a prova antes. Consultar antes
    parece prudente e nao e: prova mede o estado da tela, e um estado que ja
    existia no carregamento (um iframe embutido, um elemento que sempre esteve
    la) passa por reacao e faz o clique ser pulado. Foi assim que este botao
    deixou de ser clicado. Evidencia so vale como MUDANCA, e antes do primeiro
    clique nao ha com o que comparar.

    Da segunda em diante a prova e consultada, sim: ai ela protege contra o
    erro oposto — repetir um clique que ja pegou manda dois envios seguidos, e
    e assim que o gov.br passa a tratar a sessao como acesso automatizado.
    """
    tentativas = CLIQUES_GOVBR if tentativas is None else tentativas
    espera_ms = ESPERA_PROVA_MS if espera_ms is None else espera_ms
    for tentativa in range(1, tentativas + 1):
        if tentativa > 1:
            try:
                if prova():
                    print(f"  -> {descricao}: a pagina reagiu (tardiamente).")
                    return True
            except Exception:
                pass
        via = _clicar_por_todas_as_vias(page, localizar, seletor_css, descricao,
                                        via_inicial=tentativa - 1)
        if not via:
            print(f"  -> {descricao}: nenhuma via de clique funcionou.")
            return _esperar_reacao(prova, espera_ms)
        print(f"  -> {descricao}: clicado ({via}); conferindo se a pagina reagiu...")
        if _esperar_reacao(prova, espera_ms):
            print(f"  -> {descricao}: a pagina reagiu.")
            return True
        print(f"  -> [tentativa {tentativa}/{tentativas}] {descricao}: "
              "nada mudou na tela; o clique foi em falso.")
    print(f"  -> [AVISO] {descricao}: a pagina nao reagiu a {tentativas} cliques.")
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


# A ultima mensagem de recusa que o eCAC mostrou na troca de perfil.
#
# Existe porque `garantir_acesso_ecac` devolve apenas True/False, e o texto e
# apagado da tela logo em seguida: `_fechar_popup()` remove o dialogo, e com ele
# o <p class="mensagemErro">. Quem chamava olhava a tela DEPOIS e nao achava
# nada — em producao isso virou "Falha no login" para procuracao expirada,
# cancelada, inexistente e ate para a deteccao de automacao, tudo no mesmo
# balaio. A planilha do usuario recebia o mesmo texto vago em todas as linhas.
_ULTIMA_RECUSA = {"mensagem": ""}

# Ate onde a ultima chamada CHEGOU. Vira True so quando o CNPJ ja esta no campo
# e o "Alterar" vai ser acionado.
#
# Existe porque tudo o que vem ANTES disso — abrir o Chrome, alcancar o eCAC,
# passar pelo gov.br, resolver o captcha, apresentar o certificado — nao tem
# nada a ver com o CNPJ que se quer representar. Um `goto` que estourou por
# timeout e problema de rede ou de navegador, e visto em producao ele foi
# registrado na planilha do usuario como falha DAQUELA empresa, que assim
# passaria a ser pulada na proxima execucao sem nunca ter sido tentada.
_CHEGOU_NA_TROCA = {"sim": False}


def tentou_trocar_perfil() -> bool:
    """True se a ultima chamada chegou a acionar o "Alterar" com o CNPJ.

    False significa que a empresa NAO foi tentada: o que falhou foi o caminho
    ate o eCAC, e isso vale para qualquer CNPJ igualmente.
    """
    return _CHEGOU_NA_TROCA["sim"]


def ultima_recusa_de_perfil() -> str:
    """A mensagem da ultima recusa de troca de perfil, ou "" se nao houve.

    Vale ate a proxima chamada de `garantir_acesso_ecac`, que a limpa.
    """
    return _ULTIMA_RECUSA["mensagem"]


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

    _ULTIMA_RECUSA["mensagem"] = ""
    _CHEGOU_NA_TROCA["sim"] = False

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
        limite_busca = time.monotonic() + 15.0
        loc_govbr, sel_govbr = _achar_govbr(page)
        while loc_govbr is None and time.monotonic() < limite_busca:
            try:
                page.wait_for_timeout(300)
            except Exception:
                break
            loc_govbr, sel_govbr = _achar_govbr(page)
        if loc_govbr is None:
            print("  -> botao 'Entrar com gov.br' nao encontrado.")
            registrar_erro("Login: botao 'Entrar com gov.br' nao encontrado.")
            return False

        # Duas esperas, e elas respondem a coisas diferentes: o documento ter
        # terminado de carregar, e a pagina ter carregado QUEM ATENDE o clique.
        _pagina_pronta(page)
        _pronto_para_govbr(page)

        if not _clicar_ate_reagir(page,
                                  lambda: _achar_govbr(page, timeout_ms=500)[0],
                                  sel_govbr, _prova_govbr(page, page.url),
                                  "'Entrar com gov.br'"):
            registrar_erro("Login: 'Entrar com gov.br' nao produziu reacao na pagina.")
            return False

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

    # Seletores do "x" que fecha o dialogo de perfil, do mais preciso ao mais
    # desesperado. A pagina do eCAC tem VARIOS ui-dialog, quase todos ocultos —
    # por isso cada seletor e resolvido em TODOS os elementos que casam, nunca
    # so no primeiro: `.first` cai no "x" de um dialogo escondido.
    SEL_FECHAR_POPUP = [
        'div.ui-dialog:has(#formPJ) a.ui-dialog-titlebar-close',
        'div.ui-dialog:has(#txtNIPapel2) a.ui-dialog-titlebar-close',
        'a.ui-dialog-titlebar-close:has(span.ui-icon-closethick)',
        'a.ui-dialog-titlebar-close',
        'span.ui-icon-closethick',
        'xpath=/html/body/div[11]/div[1]/a',
    ]

    def _popup_aberto() -> bool:
        """True enquanto o dialogo de perfil estiver na tela."""
        for sel in ("#txtNIPapel2", "div.ui-dialog:has(#formPJ)"):
            try:
                if page.locator(sel).first.is_visible(timeout=500):
                    return True
            except Exception:
                continue
        return False

    def _mensagem_de_erro() -> str:
        """O texto da recusa que o eCAC mostrou, COMO ESTA NA TELA.

        Ancorado na CLASSE `mensagemErro`, com que o portal marca toda recusa
        da troca de perfil. A lista de frases conhecidas fica como reserva: uma
        redacao nova ("...expirou em 28/02/2023") nao esta em lista nenhuma, e
        precisa ser reconhecida do mesmo jeito.
        """
        for sel in ("p.mensagemErro", ".mensagemErro"):
            try:
                candidatos = page.locator(sel).all()
            except Exception:
                continue
            for loc in candidatos:
                try:
                    if not loc.is_visible(timeout=300):
                        continue
                    texto = " ".join((loc.inner_text() or "").split())
                except Exception:
                    continue
                if texto:
                    return texto
        for msg in ERROS_FATAIS + [ERRO_ACESSO_AUTOMATIZADO]:
            try:
                if page.locator(f"text={msg}").first.is_visible():
                    return msg
            except Exception:
                continue
        return ""

    def _fechar_popup() -> bool:
        """Fecha o dialogo de perfil. NAO desloga.

        Sair com Seguranca aqui derrubava a sessao a cada recusa de procuracao:
        a empresa SEGUINTE, do mesmo certificado, era obrigada a refazer o login
        inteiro — com captcha, minutos e mais uma sessao no limite do gov.br.
        Quem abriu a sessao e quem decide encerra-la.
        """
        if not _popup_aberto():
            return True
        print("  -> Fechando popup de perfil...")
        for sel in SEL_FECHAR_POPUP:
            try:
                alvos = page.locator(sel).all()
            except Exception:
                continue
            for alvo in alvos:
                try:
                    if not alvo.is_visible(timeout=300):
                        continue
                    alvo.click(timeout=3_000)
                except Exception:
                    continue
                if not _popup_aberto():
                    return True
        try:
            page.keyboard.press("Escape")
        except Exception:
            pass
        if not _popup_aberto():
            print("  -> popup fechado com Esc.")
            return True
        print("  -> [AVISO] o popup de perfil continuou na tela.")
        return False

    def _clicar_alterar() -> bool:
        """Aciona o "Alterar" do formPJ — UMA VEZ SO.

        A escada antiga (click -> force-click -> DOM click) mandava ate TRES
        envios do mesmo formulario numa unica passagem, e o eCAC le repeticao
        como "acesso automatizado". Pior: o timeout do Playwright nao distingue
        "nao cliquei" de "cliquei e a pagina mudou embaixo de mim", e o segundo
        caso e o comum — o force-click seguinte era um segundo envio de um
        clique que ja tinha dado certo.

        Por isso: um clique, e quem julga o resultado e a TELA.
        """
        try:
            page.locator('#formPJ input[value="Alterar"], '
                         '#formPJ input[onclick*="validaCaptcha"], '
                         '#formPJ input[type="submit"]').first.click(timeout=5_000)
            print("  -> clicado (uma vez).")
            return True
        except Exception as e:
            print(f"  -> o clique nao confirmou ({type(e).__name__}); "
                  "deixando a tela decidir.")
            return True

    def _desfecho(timeout_ms: int = 25_000) -> tuple[str, str]:
        """Espera a TELA responder ao unico clique: (estado, mensagem).

        estado: "ok" (popup fechou), "erro" (mensagem na tela) ou "timeout".

        Poll curto em vez de pausa fixa: o caminho feliz sai no instante em que
        o popup fecha, e o de erro assim que a mensagem aparece. A pausa cega de
        2,5s de antes olhava a tela cedo demais — a resposta do portal ainda nao
        tinha chegado, e o codigo concluia "nada aconteceu" e clicava de novo.

        O popup fechado e confirmado DUAS vezes: durante um update do PrimeFaces
        o dialogo some por um instante e volta, e um "ok" nesse intervalo daria
        a troca por feita sem ela ter acontecido.
        """
        limite = time.monotonic() + timeout_ms / 1000.0
        fechado_antes = False
        while True:
            msg = _mensagem_de_erro()
            if msg:
                return "erro", msg
            fechado = not _popup_aberto()
            if fechado and fechado_antes:
                return "ok", ""
            fechado_antes = fechado
            if time.monotonic() >= limite:
                return "timeout", ""
            try:
                page.wait_for_timeout(400)
            except Exception:
                return "timeout", ""

    # UM envio por passagem. A segunda passagem existe SO para o caso de a tela
    # nao ter reagido de forma nenhuma — ai o primeiro clique provavelmente nao
    # chegou ao botao. Qualquer mensagem de erro encerra aqui: nem a procuracao
    # nem o "acesso automatizado" mudam de resposta com um clique a mais, e no
    # segundo caso a repeticao e justamente a causa.
    MAX_ENVIOS_ALTERAR = 2
    for tentativa_alterar in range(1, MAX_ENVIOS_ALTERAR + 1):
        # Daqui em diante a falha e DESTA empresa: o CNPJ ja esta no campo.
        _CHEGOU_NA_TROCA["sim"] = True
        print(f"Clicando no botao 'Alterar' (formPJ) — envio {tentativa_alterar} "
              f"de no maximo {MAX_ENVIOS_ALTERAR}...")
        _clicar_alterar()

        estado, erro = _desfecho()

        if estado == "erro":
            registrar_erro(erro)
            print(f"  -> [RECUSADO pelo eCAC] {erro}")
            # Guardado ANTES de fechar: o popup leva a mensagem embora.
            _ULTIMA_RECUSA["mensagem"] = erro
            _fechar_popup()
            return False

        if estado == "ok":
            break

        # "timeout": a tela nao disse nem sim nem nao.
        if tentativa_alterar < MAX_ENVIOS_ALTERAR:
            print("  -> a tela nao reagiu ao 'Alterar'; um segundo envio, agora "
                  "bem separado do primeiro.")
            continue
        print("  -> popup NAO fechou: a troca de perfil nao se confirmou.")
        registrar_erro("Troca de perfil nao confirmada: o popup do formPJ "
                       "continuou na tela apos o envio.")
        _fechar_popup()
        return False

    try:
        page.wait_for_load_state("domcontentloaded", timeout=15_000)
    except Exception:
        pass
    print("  -> perfil de acesso alterado.")
    print("Concluido.")
    return True
"""Login no eCAC via Patchright com client_certificates.

Uso:
    from ecac_login import fazer_login
    p, context, page = fazer_login(cnpj="<CNPJ da empresa>")

Pre-requisitos no .env do projeto chamador:
    CERT_PFX_PATH=meu_certificado.pfx   (nome do arquivo em LoginEcac/Certificados/)
    CERT_PFX_PASSPHRASE=senha-do-pfx    (opcional: lida automaticamente do senhas.json)
    GEMINI_API_KEY=chave-gemini
"""
import hashlib
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

# Quantas vezes RELANCAR o Chrome quando o portal acusa acesso automatizado.
# O bloqueio e da JANELA, nao da conta: o gov.br olha atributos da sessao, e
# uma janela ja marcada continua marcada por mais que se insista nela. Quem
# limpa e um Chrome novo — por isso a tentativa mora em `main`, onde o
# navegador nasce, e nao no meio do fluxo de login.
#
# Com teto de proposito. "Ate parar de aparecer" vira um laco infinito abrindo
# e fechando Chrome quando o bloqueio olha o IP, que relancamento nenhum muda.
# Duas, nao quatro. Cada volta custa um captcha resolvido — tempo e chamadas de
# API — para ser recusada no mesmo ponto, e uma rajada de logins seguidos e
# justamente o padrao que piora a reputacao da sessao no portal. Quando o
# bloqueio e passageiro, a segunda volta resolve; quando nao e, insistir mais
# nao vai resolver e ainda cobra o preco.
TENTATIVAS_ACESSO_BLOQUEADO = 2
# Reabrir na hora costuma cair no mesmo bloqueio, e ainda arrisca achar o
# diretorio de perfil ainda preso pelo Chrome anterior.
ESPERA_ACESSO_BLOQUEADO_S = 5


class AcessoBloqueado(Exception):
    pass


class DispositivosMaximo(Exception):
    pass


class LoginCancelado(Exception):
    """Quem chamou pediu para abortar antes de o login terminar.

    Existe porque o login e a etapa mais longa e menos interrompivel da
    execucao: captcha, certificado, e agora o relancamento do navegador. Sem um
    jeito de perguntar "ainda quero isto?", um pedido de parada so era atendido
    depois de tudo terminar — e quem apertou o botao via a automacao seguir
    abrindo navegador e resolvendo captcha como se nada tivesse acontecido.
    """


class PortalIndisponivel(Exception):
    """O portal nao respondeu — rede, DNS ou o servidor da Receita fora do ar.

    Existe para separar "o PORTAL falhou" de "esta EMPRESA falhou". Sao a mesma
    coisa para o codigo e coisas opostas para o usuario: uma empresa recusada ja
    era, e um portal fora do ar volta em minutos.

    Em producao (27/08/2026, 10:39 as 10:42) o cav.receita.fazenda.gov.br ficou
    fora tres minutos. Como o `goto` apenas devolvia False, cada empresa da fila
    entrou, bateu no mesmo ERR_CONNECTION_TIMED_OUT e saiu como "nao tentada":
    cinco queimadas em tres minutos. Uma delas ja estava na repescagem, gastou a
    ultima chance que tinha e terminou a execucao sem nunca ter sido tentada de
    verdade.

    Quem trata espera e tenta de novo, sem consumir a proxima da fila.
    """


# Assinaturas de falha de REDE nas excecoes do Playwright. O Chromium prefixa os
# erros de rede com "net::ERR_"; o restante cobre o que ele reporta antes de ter
# um erro de rede formado (DNS que nao resolve, conexao recusada).
_MARCAS_DE_REDE = (
    "net::err_",
    "err_connection",
    "err_name_not_resolved",
    "err_internet_disconnected",
    "err_address_unreachable",
    "err_network_changed",
    "err_timed_out",
    "err_empty_response",
)


def _falha_de_rede(e: Exception) -> bool:
    """True quando a excecao veio da REDE, e nao da pagina.

    O TimeoutError do `goto` entra: com `wait_until="commit"` ele so estoura se
    o servidor nao chegou a responder nada — pagina lenta ja teria commitado.
    """
    if type(e).__name__ == "TimeoutError":
        return True
    texto = str(e).lower()
    return any(marca in texto for marca in _MARCAS_DE_REDE)


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

    Todos os usos desta função são **guardas**: procuram a mensagem de acesso
    bloqueado ou a de número máximo de dispositivos. Deixar a exceção subir faz
    a guarda derrubar o login inteiro por não ter conseguido ler o HTML — mais
    frágil do que aquilo que ela protege. E o sintoma não sugere a causa: quem
    lê o erro procura defeito na página, não uma leitura feita cedo demais.

    Eles ficam justamente nos pontos de maior movimento — depois do `goto`, em
    volta do clique no gov.br, depois de submeter um captcha (que por definição
    navega) e depois de apresentar o certificado. Algumas centenas de
    milissegundos depois a mesma leitura funciona.

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


# ── Onde mora o perfil do Chrome ─────────────────────────────────────────────
# O perfil (user-data-dir) recebe escrita CONTINUA do Chrome: SQLite em modo WAL
# (cookies, historico), LevelDB, cache em disco e travas de arquivo. Num disco que
# NAO e local de verdade isso TRAVA o navegador — cliques parados em "scrolling
# into view", a pagina deixa de responder e o Chrome acaba caindo
# (TargetClosedError) depois de alguns documentos. E exatamente o que acontece
# quando o operador roda o .exe de DENTRO do Google Drive, porque o perfil nasce
# ao lado do .exe.
#
# Pegadinha medida: o Google Drive para desktop (G:, H:, ...) se apresenta ao
# Windows como disco FIXO — so que FAT32 e com a flag de armazenamento remoto.
# Por isso a checagem nao pode ser so "e disco fixo?": exige NTFS/ReFS e ausencia
# da flag. Qualquer outra coisa (Drive, rede, pen drive) leva o perfil para
# %LOCALAPPDATA%. O nome da pasta final continua `chrome_debug_profile` — ha
# automacoes que localizam o Chrome pela linha de comando com esse nome.
_DRIVE_FIXED = 3
_FILE_SUPPORTS_REMOTE_STORAGE = 0x100
_SISTEMAS_ARQUIVO_LOCAIS = {"NTFS", "REFS"}


def disco_local_confiavel(caminho) -> bool:
    """True se `caminho` esta num disco LOCAL de verdade: fixo, NTFS/ReFS e sem a
    flag de armazenamento remoto. False para Google Drive, rede, pen drive — e
    tambem quando nao da para saber (na duvida, o perfil vai para o disco local)."""
    try:
        import ctypes
        raiz = os.path.splitdrive(os.path.abspath(str(caminho)))[0]
        if not raiz or raiz.startswith("\\\\"):
            return False  # caminho UNC (\servidor\...) = rede
        raiz += "\\"
        k32 = ctypes.windll.kernel32
        if k32.GetDriveTypeW(raiz) != _DRIVE_FIXED:
            return False
        fs = ctypes.create_unicode_buffer(261)
        flags = ctypes.c_ulong()
        if not k32.GetVolumeInformationW(raiz, None, 0, None, None,
                                         ctypes.byref(flags), fs, 261):
            return False
        if fs.value.upper() not in _SISTEMAS_ARQUIVO_LOCAIS:
            return False
        return not (flags.value & _FILE_SUPPORTS_REMOTE_STORAGE)
    except Exception:
        return False


def dir_perfil_chrome(project_dir, perfil_dir=None) -> Path:
    """Pasta do perfil do Chrome para `project_dir`.

    Ordem: `perfil_dir` explicito > `ECAC_PERFIL_DIR` do ambiente/.env >
    `<project_dir>/chrome_debug_profile` quando o projeto esta num disco local
    confiavel > `%LOCALAPPDATA%/SaveEcac/perfis/<projeto>-<hash>/chrome_debug_profile`.
    O hash do caminho separa dois projetos de mesmo nome. Funcao PURA quanto ao
    filesystem (nao cria nada)."""
    if perfil_dir:
        return Path(perfil_dir)
    do_ambiente = os.getenv("ECAC_PERFIL_DIR", "").strip()
    if do_ambiente:
        return Path(do_ambiente)
    project_dir = Path(project_dir)
    if disco_local_confiavel(project_dir):
        return project_dir / "chrome_debug_profile"
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    absoluto = os.path.abspath(str(project_dir))
    chave = hashlib.sha1(absoluto.lower().encode("utf-8")).hexdigest()[:10]
    nome = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(absoluto).name).strip("_")[:40] or "projeto"
    return Path(base) / "SaveEcac" / "perfis" / f"{nome}-{chave}" / "chrome_debug_profile"


def _avisar_perfil_realocado(project_dir, perfil) -> None:
    """Uma linha no log quando o perfil NAO fica ao lado do projeto. Sem o caminho:
    ele traz o nome do usuario do Windows e a regra do modulo e nao imprimi-lo."""
    if Path(perfil) != Path(project_dir) / "chrome_debug_profile":
        print("[perfil] Projeto fora de um disco local (Google Drive, rede ou pen drive) "
              "ou pasta definida por ECAC_PERFIL_DIR: o perfil do Chrome fica na pasta "
              "local do usuario (%LOCALAPPDATA%/SaveEcac/perfis), para o navegador "
              "nao travar.")


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


def _pkcs12_moderno(cert_pfx_path, cert_pfx_passphrase):
    """O mesmo par chave+certificado reserializado em PBES2/AES-256, em BYTES.

    POR QUE ISTO EXISTE. Quem apresenta o certificado ao servidor não é o
    Chrome: é o Node do Playwright, que intercepta o TLS e monta o contexto
    seguro com o OpenSSL 3 dele. E o OpenSSL 3 recusa as cifras legadas de
    PKCS#12 — que são exatamente as que a AC brasileira costuma entregar.

    MEDIDO em 27/10/2026, com Patchright 1.60.1, comparando dois certificados
    reais do mesmo Cofre (só a ESTRUTURA dos arquivos, sem decifrar nada):

        o que funcionava:  PBES2 / PBKDF2-SHA256 / AES-256-CBC, MAC SHA-256
        o que falhava:     pbeWithSHAAnd40BitRC2-CBC nos certificados,
                           pbeWithSHAAnd3-KeyTripleDES-CBC na chave, MAC SHA-1

    O segundo derruba o lançamento em menos de um segundo:

        Error: BrowserType.launch_persistent_context: Failed to load client
        certificate: Unsupported TLS certificate. Most likely, the security
        algorithm of the given certificate was deprecated by OpenSSL.

    Reproduzido com um `.pfx` sintético de cifra idêntica e resolvido pela
    conversão: o MESMO par, reserializado em AES-256, lança normalmente. O
    certificado não muda — muda o empacotamento do arquivo.

    `None` quando não dá para converter: arquivo ausente, senha que não abre,
    PFX sem chave privada, ou sem senha para reencriptar. Nesses casos o
    caminho original segue para o Playwright exatamente como antes — a
    conversão é um GANHO, e não pode virar um jeito novo de falhar.

    NADA É ESCRITO EM DISCO: a API aceita `pfx` em bytes, então a chave
    convertida vive na memória do processo e morre com ele.
    """
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        pkcs12,
    )

    senha = (cert_pfx_passphrase or "").encode("utf-8")
    if not senha:
        # Sem senha não há o que reencriptar mantendo o contrato: a
        # `passphrase` continua indo para o Playwright, e um PFX que abre sem
        # senha é um PFX que ele já abre.
        return None
    try:
        bruto = Path(cert_pfx_path).read_bytes()
        chave, certificado, cadeia = pkcs12.load_key_and_certificates(bruto, senha)
        if chave is None or certificado is None:
            return None
        return pkcs12.serialize_key_and_certificates(
            b"certificado", chave, certificado, cadeia or None,
            BestAvailableEncryption(senha))
    except Exception:  # noqa: BLE001 — qualquer tropeço cai no caminho de antes
        return None


def _build_client_certificates(cert_pfx_path, cert_pfx_passphrase,
                               cert_pfx_bytes=None):
    """Monta `client_certificates` a partir do PFX recebido por argumento.

    Uma entrada por origem: `client_certificates` casa por ORIGEM EXATA, sem
    wildcard. A passphrase é repassada como veio — a API aceita `str | None`, e
    exigir senha não vazia inventaria uma regra que o contrato não tem.

    `cert_pfx_bytes` é o arquivo JÁ convertido por `_pkcs12_moderno`. Vindo
    preenchido, ele vai como `pfx` e o caminho não é usado; vindo `None`, o
    `pfxPath` segue como sempre foi. A LEITURA DO ARQUIVO FICA FORA DAQUI de
    propósito: esta função e `_montar_launch_kwargs` são puras, e é isso que
    permite conferir a configuração do navegador sem Chrome e sem certificado.

    Nota histórica: esta função devolvia `None` incondicionalmente, com a
    justificativa de que `client_certificates` falharia com a cadeia ICP-Brasil
    (SSL alert 40). Essa hipótese foi REFUTADA POR MEDIÇÃO: o probe DEV
    `AUT-0008` completou o handshake mTLS e chegou à home autenticada do eCAC
    por este exato caminho, com Patchright 1.60.1.
    """
    arquivo = ({"pfx": cert_pfx_bytes} if cert_pfx_bytes
               else {"pfxPath": str(cert_pfx_path)})
    return [
        {"origin": origin, **arquivo, "passphrase": cert_pfx_passphrase}
        for origin in CERT_ORIGINS
    ]


def _montar_launch_kwargs(user_data_dir: str, *,
                          cert_pfx_path=None,
                          cert_pfx_passphrase=None,
                          cert_subject_cn: str | None = None,
                          cert_pfx_bytes=None) -> dict:
    """Monta os kwargs de lançamento do Chrome. Função PURA.

    Não abre navegador, não toca filesystem e não lê segredo — existe para que a
    configuração de certificado seja testável sem Chrome. Quem lê o `.pfx` é
    `_pkcs12_moderno`, e o resultado chega aqui em `cert_pfx_bytes`.

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

    # Gravacao de HAR, ligada so por ambiente (ECAC_HAR_PATH). Existe para uma
    # comparacao especifica: o mesmo processo feito A MAO no Chrome exporta um
    # HAR pelo DevTools, e este aqui produz o artefato equivalente do lado
    # automatizado. Sem os dois no mesmo formato, comparar "manual e mais
    # rapido" com o log da automacao e comparar impressao com medida.
    #
    # `record_har_content="omit"` descarta os CORPOS das respostas: o que
    # interessa e o tempo de cada requisicao, e sem isso o arquivo passa de
    # centenas de MB. ATENCAO: o HAR ainda carrega cabecalhos e cookies de
    # sessao — trate como credencial.
    har = os.getenv("ECAC_HAR_PATH", "").strip()
    if har:
        kwargs["record_har_path"] = har
        kwargs["record_har_content"] = "omit"

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
        cert_pfx_path, cert_pfx_passphrase, cert_pfx_bytes)
    return kwargs


# Orcamento de tempo de UMA chamada ao solver, em segundos.
#
# Sem ele o solver nao tem teto nenhum: `solve_hcaptcha(page)` deixa
# `politica.fim = None`, e com `fim` None a propriedade `esgotado` e sempre
# False — logo TODAS as verificacoes de orcamento dentro do solver viram no-op.
# Os lacos aninhados entao ficam livres para o pior caso do proprio codigo:
# 3 modelos x MAX_GEMINI_TRIES(3) x max_rounds(5) x max_rounds(6), tudo isso
# vezes as 3 tentativas daqui. Foi assim que uma etapa de captcha comeu minutos
# no log de 28/08, com ReadTimeout em modelo apos modelo.
#
# 120s vem da aritmetica do solver: GEMINI_TIMEOUT_MS e 25s e a bancada tem 3
# modelos, entao uma cadeia cheia custa ~75s; sobra espaco para o screenshot,
# clique e verificacao. Subiu de 90s para dar FOLGA em MAQUINAS/REDES LENTAS,
# onde o proprio carregamento dos tiles ja consumia o orcamento antes da 1a
# chamada ao Gemini (visto em log com 'orçamento de tempo esgotado' na rodada 1).
# Com as 3 tentativas daqui, a etapa inteira custa no maximo ~6 min, nao ilimitado.
ORCAMENTO_CAPTCHA_S = 120.0


def _try_solve_captcha(page, etapa: str, max_attempts: int = 3, metrics_fn=None) -> bool:
    print(f"[{etapa}] Verificando hCaptcha (ate {max_attempts} tentativas)...")
    for tentativa in range(1, max_attempts + 1):
        try:
            resultado = solve_hcaptcha(page, deadline_s=ORCAMENTO_CAPTCHA_S)
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

# Janela para o formPJ se enviar SOZINHO antes de clicarmos no "Alterar". Ver
# `_enviar_uma_vez`: em producao, todo envio que o eCAC aceitou foi da propria
# pagina, e todo envio nosso que chegou com a procuracao valida virou "acesso
# automatizado".
#
# 2,5s porque nos casos observados a reacao ja estava em curso quando o `[diag]`
# rodava, algumas centenas de milissegundos depois do `fill`. E o custo maximo:
# quando ninguem envia, paga-se a janela e clica-se igual.
ESPERA_ENVIO_ESPONTANEO = 2_500
PASSO_ENVIO_ESPONTANEO = 250

# "Acesso automatizado" NA TROCA DE PERFIL — o <p class="mensagemErro"> "Nao foi
# possivel alterar o perfil de acesso. A execucao possui atributos que
# caracteriza acesso automatizado. Tente novamente mais tarde".
#
# Nao e o BLOQUEIO do gov.br na tela de login (`MENSAGEM_ACESSO_BLOQUEADO`), que
# condena a janela: aqui a sessao continua autenticada, e a propria mensagem pede
# outra tentativa. Era tratado como recusa fatal — o popup fechava, `main`
# fechava o navegador e quem chamou abria outro, com login e captcha novos
# (relato do operador, 19/10/2026). Agora: espera e reenvia NA MESMA janela.
#
# Com teto, de proposito: um bloqueio que nao passa viraria um laco sem fim com
# o navegador aberto. 30 x 10s, ~5 a 7 min por empresa; quem chama pode mudar
# por chamada (`garantir_acesso_ecac(..., insistencias_acesso_automatizado=)`).
ESPERA_ACESSO_AUTOMATIZADO_NA_TROCA_S = 10
INSISTENCIAS_ACESSO_AUTOMATIZADO_NA_TROCA = 30
# Reenvios para o que NAO e "acesso automatizado": a tela que nao reagiu ao
# envio, e o "CNPJ nao preenchido" (race do preenchimento). Um, como sempre foi.
REENVIOS_SEM_RESPOSTA = 1


def _eh_acesso_automatizado(mensagem: str) -> bool:
    return "acesso automatizado" in (mensagem or "").lower()


def _eh_cnpj_nao_preenchido(mensagem: str) -> bool:
    texto = (mensagem or "").lower()
    return "cnpj" in texto and ("não preenchido" in texto or "nao preenchido" in texto)


def _enviar_ate_o_desfecho(enviar, desfecho, preparar_reenvio, esperar_s, *,
                           insistencias: int, reenvios: int = None):
    """Envia o formPJ ate o eCAC responder de vez. Devolve `(estado, mensagem, via)`.

    `estado`: "ok" (trocou), "erro" (recusa; `mensagem` e o texto do portal) ou
    "timeout" (a tela nao respondeu). A politica:

    - "acesso automatizado": espera `ESPERA_ACESSO_AUTOMATIZADO_NA_TROCA_S` e
      reenvia, ate `insistencias` vezes, NA MESMA janela;
    - "CNPJ nao preenchido" e tela que nao reagiu: `reenvios` reenvio(s);
    - toda outra recusa (procuracao, CNPJ invalido) encerra na hora — nenhuma
      muda de resposta com outra tentativa.

    Cada envio continua sendo UM so: quem envia e `enviar()`, que deixa a propria
    pagina enviar e so clica se ela nao enviar (`_enviar_uma_vez`).

    `enviar()` devolve a via; `desfecho()` devolve `(estado, mensagem)`;
    `preparar_reenvio(motivo)` limpa a recusa da tela e repreenche o CNPJ;
    `esperar_s(segundos)` espera. Parametros para que a POLITICA seja testada sem
    navegador.
    """
    reenvios = REENVIOS_SEM_RESPOSTA if reenvios is None else reenvios
    insistidas = 0
    reenviados = 0
    while True:
        via = enviar()
        estado, erro = desfecho()
        if estado == "ok":
            return "ok", "", via
        if estado == "erro" and _eh_acesso_automatizado(erro):
            if insistidas >= insistencias:
                return "erro", erro, via
            insistidas += 1
            print(f"  -> [ACESSO AUTOMATIZADO | via={via}] o eCAC pediu para tentar mais "
                  f"tarde ({insistidas}/{insistencias}). Esperando "
                  f"{ESPERA_ACESSO_AUTOMATIZADO_NA_TROCA_S}s e reenviando NA MESMA janela...")
            esperar_s(ESPERA_ACESSO_AUTOMATIZADO_NA_TROCA_S)
            preparar_reenvio("acesso_automatizado")
            continue
        if estado == "erro" and not _eh_cnpj_nao_preenchido(erro):
            return "erro", erro, via
        if reenviados >= reenvios:
            return estado, erro, via
        reenviados += 1
        if estado == "erro":
            print(f"  -> [RETRIAVEL | via={via}] {erro} — repreenchendo o CNPJ e reenviando...")
            preparar_reenvio("cnpj_nao_preenchido")
        else:
            # Repreenche tambem: se a pagina esvaziou o campo e nao respondeu,
            # sem o CNPJ de volta nem ela nem o clique teriam o que enviar.
            print("  -> a tela nao reagiu ao 'Alterar'; um segundo envio, agora "
                  "bem separado do primeiro.")
            preparar_reenvio("sem_resposta")


# Checkpoint de "Parar", registrado por quem hospeda a automacao (o `run.py` do
# Consulta CO). Este pacote nao conhece a janela de progresso — so o gancho.
#
# Existe porque as esperas LONGAS deste arquivo eram cegas: `wait_for_url` de 90s
# e `wait_for(#btnPerfil)` de 60s bloqueiam a thread inteira sem imprimir nem
# olhar nada. Nesse intervalo o botao "Parar" nao fazia efeito nenhum — dois
# minutos e meio de "aperta e nao acontece", que foi o relato.
_GATE = None


def registrar_gate(callback) -> None:
    """Registra (ou desarma, com None) o checkpoint de parada."""
    global _GATE
    _GATE = callback


def _checkpoint() -> None:
    """Deixa a parada do usuario valer aqui.

    So fora da thread principal, pela mesma razao do gate do `run.py`: bloquear
    a principal congelaria a janela que mostra o "Parando...".
    """
    if (_GATE is not None
            and threading.current_thread() is not threading.main_thread()):
        _GATE()


# Teto da espera pelo botao "Seu certificado digital" (ou pelo login ja feito).
# Mesmo total da espera antiga: 20s no 1o seletor + 2s em cada um dos outros.
ESPERA_BOTAO_CERTIFICADO_MS = 26_000


def _esperar_ate(page, condicao, timeout_ms: int, passo_ms: int = 300) -> bool:
    """Espera `condicao()` virar True, em fatias, obedecendo o "Parar".

    Em fatias, e nao numa espera unica do Playwright, justamente para que o
    checkpoint tenha onde acontecer. `condicao` que estoura conta como "ainda
    nao"; guia fechada encerra na hora.
    """
    limite = time.monotonic() + timeout_ms / 1000.0
    while True:
        try:
            if page.is_closed():
                return False
            if condicao():
                return True
        except Exception:
            pass
        if time.monotonic() >= limite:
            return False
        try:
            page.wait_for_timeout(passo_ms)
        except Exception:
            return False
        _checkpoint()


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


def _procurar_govbr(page, segundos: float = 15.0):
    """`_achar_govbr` insistindo por ate `segundos`. (locator, seletor) ou (None, "").

    Em fatias, e nao num timeout unico, porque assim a espera obedece ao botao
    "Parar" e porque o botao costuma aparecer no primeiro instante — quem
    espera de verdade e a excecao.
    """
    limite = time.monotonic() + segundos
    loc, sel = _achar_govbr(page)
    while loc is None and time.monotonic() < limite:
        try:
            page.wait_for_timeout(300)
        except Exception:
            break
        _checkpoint()
        loc, sel = _achar_govbr(page)
    return loc, sel


# Telas de erro do proprio eCAC, colhidas em producao (03/09/2026):
#
#   "Ocorreu um erro. (Código: 0)  Erro desconhecido."
#   "Atenção. (Código: 10000 - 380D07CF)  Prezado Usuário, não foi possível
#    validar os seus dados nas bases cadastrais da Receita Federal. Por favor,
#    tente mais tarde."
#
# Sao paginas normais do portal — carregam, tem cabecalho, e nao tem botao
# nenhum de login. Duas empresas foram descartadas por causa delas em menos de
# um minuto, e a terceira, no mesmo minuto, logou sem problema.
# So a MENSAGEM decide. O link "Retornar para a pagina inicial do e-CAC", que
# acompanha essas telas, de proposito NAO entra aqui: e um link comum, que pode
# existir em telas saudaveis, e um falso positivo custaria uma recarga a mais em
# cada uma das 1150 empresas.
_MENSAGENS_DE_ERRO_ECAC = (
    "ocorreu um erro",
    "não foi possível validar os seus dados",
    "nao foi possivel validar os seus dados",
)


def _erro_do_ecac(page) -> str:
    """A frase de erro que o eCAC pos na tela, ou "" se a tela nao e de erro.

    Le o TEXTO, e nao a URL: o portal serve estas telas na mesma URL do eCAC —
    tanto que o passo anterior ja concluia "URL indica eCAC mas dashboard nao
    carregou" sem saber dizer por que.

    Chamada em TODA empresa, logo depois do goto, entao precisa ser barata: e
    uma leitura so do texto ja carregado, sem espera nenhuma.
    """
    try:
        if page.is_closed():
            return ""
        texto = (page.locator("body").inner_text(timeout=3_000) or "")
    except Exception:
        return ""
    if not any(m in texto.lower() for m in _MENSAGENS_DE_ERRO_ECAC):
        return ""
    # Devolver a tela inteira so encheria o log; a frase util e uma linha.
    for linha in (l.strip() for l in texto.splitlines()):
        if any(m in linha.lower() for m in _MENSAGENS_DE_ERRO_ECAC):
            return linha[:200]
    return "página de erro do e-CAC"


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


ESPERA_OVERLAY_MS = 10_000      # quanto dar ao overlay modal para sair sozinho

# O aviso "Em breve, o acesso ao e-CAC sera desativado" e o texto do botao que o
# fecha. Ver `_fechar_aviso_de_encerramento` para o porque de a ancora ser o TEXTO.
TEXTO_CONTINUAR_NO_ECAC = "Continuar no e-CAC por enquanto"
ESPERA_AVISO_ENCERRAMENTO_MS = 3_000


def _fechar_aviso_de_encerramento(page, espera_ms: int = 0) -> bool:
    """Fecha o aviso "o e-CAC sera desativado". True quando havia um e ele saiu.

    ANCORADO NO TEXTO DO BOTAO, e nao no id do dialogo. O id
    (`#dialog-mensagem-encerramento-ecac`) era a unica ancora, e na execucao de
    20/10/2026 o aviso ficou na tela sem que nada aqui o tenha visto. O que o
    operador viu foi `<button type="button">Continuar no e-CAC por
    enquanto</button>` — sem id, sem classe. O texto e o que esse botao tem.

    E uma ESPERA, quando se pode pagar por ela: `is_visible(timeout=...)` nao
    aguarda visibilidade nenhuma — devolve o estado do instante. O aviso aparece
    DEPOIS do dashboard, e quem olha uma vez olha antes dele.

    `espera_ms=0` olha uma vez e segue. E assim que ela e chamada antes de cada
    tentativa de abrir o popup de perfil — uma vez por empresa, onde esperar
    custaria segundos multiplicados pelo lote inteiro. Depois do login, onde o
    custo e ruido perto dos dois minutos de certificado e captcha, ela e chamada
    COM espera.

    NADA aqui sobe. Fechar um aviso cosmetico nao pode ser o motivo de um login
    inteiro falhar — e a propria RESOLUCAO do locator entra no `try`, nao so a
    espera: foram os testes da sessao reaproveitada que mostraram isso, com um
    `page` que nao tinha `get_by_role` e levou um `AttributeError` de dentro
    desta funcao para fora.
    """
    try:
        botao = page.get_by_role("button", name=TEXTO_CONTINUAR_NO_ECAC).first
        if espera_ms:
            botao.wait_for(state="visible", timeout=espera_ms)
        elif not botao.is_visible():
            return False
    except Exception:
        return False

    print(f"  -> aviso do e-CAC na tela. Clicando em '{TEXTO_CONTINUAR_NO_ECAC}'...")
    # Tres vias, a mesma acao: papel, texto e DOM. A ultima nao depende de
    # ponteiro e passa mesmo com outro veu na frente.
    vias = (
        lambda: botao.click(timeout=5_000),
        lambda: page.locator(
            f'button:has-text("{TEXTO_CONTINUAR_NO_ECAC}")').first.click(timeout=5_000),
        lambda: page.evaluate(
            "(t) => { const b = [...document.querySelectorAll('button')]"
            ".find(e => (e.textContent || '').includes(t)); if (b) b.click(); }",
            TEXTO_CONTINUAR_NO_ECAC),
    )
    for clicar in vias:
        try:
            clicar()
            break
        except Exception:
            continue
    try:
        page.wait_for_timeout(800)
    except Exception:
        pass
    print("  -> aviso fechado; seguindo para o perfil de acesso.")
    return True


def _popup_fechado_significa(abriu_alguma_vez: bool) -> str:
    """O que o popup de perfil FECHADO quer dizer: "ok" ou "nao_abriu".

    "Fechado" e o estado do dialogo DEPOIS de uma troca bem-sucedida — e e
    tambem o estado ANTES de ele abrir. Ler os dois como a mesma coisa custou a
    execucao de 20/10/2026, em que o dialogo nunca apareceu e o log disse:

        -> nenhum seletor de aba bateu (talvez ja esteja ativa).
        -> input nao ficou visivel; vai tentar fallback via JS.
        [diag] inputs do formPJ: todos com visible: False
        -> [via=pagina] a propria tela enviou o formulario (reacao: ok)
        -> perfil de acesso alterado (via=pagina).

    A troca foi dada por FEITA sem nunca ter acontecido. O eCAC seguiu no perfil
    do procurador, as 32 consultas da empresa voltaram vazias e a falha apareceu
    tres telas adiante, como "o PER/DCOMP Web nao respondeu a nenhuma consulta"
    — que manda investigar sessao caida, a causa errada.

    Tres sinais na propria tela diziam que o dialogo nao tinha aberto. Nenhum
    era olhado. Agora um deles decide: sem o dialogo ter estado ABERTO, popup
    fechado nao e desfecho nenhum.
    """
    return "ok" if abriu_alguma_vez else "nao_abriu"


def _abrir_popup_de_perfil(page) -> None:
    """Clica em "Alterar perfil de acesso", contornando o overlay modal.

    O clique era seco: `page.locator("#btnPerfil").first.click()`. Quando o
    jQuery UI deixa o `div.ui-widget-overlay` na tela, ele intercepta o ponteiro,
    o Playwright reintenta por 30s e estoura — e uma empresa inteira se perdia
    por causa de um veu que ia sair sozinho em poucos segundos.

    Foi o que aconteceu em 02/09/2026 com a primeira empresa da execucao: login
    perfeito, captcha resolvido, redirecionamento concluido, e entao

        TimeoutError: Locator.click: Timeout 30000ms exceeded
        <div class="ui-widget-overlay"></div> intercepts pointer events

    A escada: esperar o overlay sair; se insistir, Esc (o dialogo do jQuery UI
    fecha com closeOnEscape); e por fim o clique pelo DOM, que dispara o mesmo
    `onclick` sem depender de ponteiro. Nao se REMOVE o overlay — apagar o veu de
    um dialogo que ainda esta aberto so esconderia o problema.
    """
    if _esperar_overlay_sair(page):
        try:
            page.locator("#btnPerfil").first.click(timeout=10_000)
            return
        except Exception as e:
            print(f"  -> o clique no 'Alterar perfil' nao pegou "
                  f"({type(e).__name__}); indo pelo DOM.")
    else:
        print("  -> o overlay modal nao saiu; abrindo o perfil pelo DOM.")

    try:
        page.keyboard.press("Escape")
    except Exception:
        pass
    # `evaluate` roda no MUNDO ISOLADO do patchright — nao enxerga `$` nem
    # nenhum global da pagina. Aqui isso nao atrapalha: o que se chama e
    # `element.click()`, e o DOM E compartilhado. O `onclick` inline do botao
    # (`$('.erro').hide(); $('#perfilAcesso').dialog(...)`) foi compilado PELA
    # pagina e roda no contexto dela, com os globais dela.
    #
    # E abrir um dialogo local, nao um envio ao portal: nada aqui se parece com
    # o "Alterar" do formPJ, que e o envio que o eCAC vigia.
    page.evaluate("() => { const b = document.getElementById('btnPerfil');"
                  " if (b) b.click(); }")


def _esperar_overlay_sair(page, timeout_ms: int = None) -> bool:
    """True quando nao ha overlay modal cobrindo a tela.

    `None` e le a constante NA CHAMADA, e nao um default no cabecalho: argumento
    default e ligado na definicao, entao `login.ESPERA_OVERLAY_MS = 1_500` de
    fora nao teria efeito nenhum — armadilha que ja custou tempo neste arquivo.
    """
    timeout_ms = ESPERA_OVERLAY_MS if timeout_ms is None else timeout_ms
    limite = time.monotonic() + timeout_ms / 1000.0
    avisou = False
    while True:
        try:
            if not page.locator("div.ui-widget-overlay:visible").count():
                if avisou:
                    print("    -> o overlay saiu; seguindo.")
                return True
        except Exception:
            return True              # sem como olhar: nao inventa bloqueio
        if not avisou:
            avisou = True
            print("    -> um overlay modal cobre a tela; esperando ele sair...")
        if time.monotonic() >= limite:
            return False
        try:
            page.wait_for_timeout(250)
        except Exception:
            return True


def _enviar_uma_vez(reacao, clicar, dormir, espera_ms: int = None,
                    passo_ms: int = None) -> str:
    """Deixa o formulario enviado UMA vez. Devolve quem enviou: "pagina" ou "clique".

    A regra: dar a propria pagina a chance de enviar, e clicar so se ela nao
    enviar. Nunca e pior do que clicar de cara — no pior caso gasta a janela e
    clica igual.

    Nao e paranoia; e o que os numeros de producao mostram. Na execucao de
    27/08/2026, as 29 trocas de perfil se dividiram assim:

        clique confirmou      ->  0 trocas | 11 "acesso automatizado" | 6 recusas
        clique NAO confirmou  -> 12 trocas |  0 "acesso automatizado" | 0 recusas

    Nenhuma troca bem-sucedida veio de um clique que confirmou. E o `[diag]`
    mostra por que: nas passagens que deram certo o botao aparecia com
    `visible: False` e o campo com `preenchido: False` — o formulario JA estava
    sendo enviado, por um ajax do PrimeFaces disparado no `fill`, e o clique
    chegava tarde (ou nem chegava).

    A leitura que fecha com os 29 casos: quando o envio e nosso, o eCAC o marca
    como automatizado; quando e da propria pagina, passa. As 6 recusas de
    procuracao confirmam que o clique CHEGA ao servidor — ele so nao e o caminho
    que o portal aceita.

    E uma hipotese, e o `via=` no log existe para mede-la: se "pagina" vier junto
    com troca concluida e "clique" junto com "acesso automatizado", esta certa.

    `reacao` devolve texto nao vazio quando a tela ja reagiu; `clicar` faz o
    clique; `dormir` recebe milissegundos. Sao parametros, e nao chamadas
    diretas, para que a POLITICA possa ser testada sem navegador.
    """
    espera_ms = ESPERA_ENVIO_ESPONTANEO if espera_ms is None else espera_ms
    passo_ms = PASSO_ENVIO_ESPONTANEO if passo_ms is None else passo_ms

    limite = time.monotonic() + espera_ms / 1000.0
    while True:
        try:
            ja_reagiu = reacao()
        except Exception:
            ja_reagiu = ""
        if ja_reagiu:
            print(f"  -> [via=pagina] a propria tela enviou o formulario "
                  f"(reacao: {ja_reagiu}); nao ha o que clicar.")
            return "pagina"
        if time.monotonic() >= limite:
            break
        dormir(passo_ms)

    clicar()
    return "clique"


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


def abrir_browser_com_certificado(project_dir: Path | str = None, perfil_dir=None):
    """Abre o Chrome com o certificado digital configurado e retorna (p, context, page).

    Não faz login no eCAC — apenas abre o navegador com os client_certificates
    carregados para autenticação direta no portal de serviços RF.

    Args:
        project_dir: Diretório do projeto chamador. Usado para o perfil Chrome e .env.
        perfil_dir: Pasta do perfil do Chrome. Padrão: ver `dir_perfil_chrome`
                    (fora do projeto quando ele não está num disco local).

    Returns:
        Tupla (p, context, page) — navegador aberto, sem navegação inicial.
    """
    if project_dir is None:
        project_dir = Path.cwd()
    project_dir = Path(project_dir)

    load_dotenv(dotenv_path=project_dir / ".env", override=True)

    user_data_dir = str(dir_perfil_chrome(project_dir, perfil_dir))
    _avisar_perfil_realocado(project_dir, user_data_dir)
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
         cert_subject_cn: str | None = None,
         cancelado=None,
         perfil_dir=None):
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
        cancelado: chamavel sem argumentos que devolve True quando quem chamou
                   quer abortar. Consultado ANTES de cada abertura de navegador
                   e durante a espera entre elas; quando devolve True, a sessao
                   e fechada e sobe `LoginCancelado`. Sem ele, nada muda.
        perfil_dir: Pasta do perfil do Chrome. Padrao: ver `dir_perfil_chrome` —
                    ao lado do projeto num disco local; em %LOCALAPPDATA% quando
                    o projeto esta no Google Drive/rede (la o Chrome trava).

    Returns:
        Tupla (p, context, page) em caso de sucesso, ou None em caso de falha.
    """
    if project_dir is None:
        project_dir = Path.cwd()
    project_dir = Path(project_dir)

    load_dotenv(dotenv_path=project_dir / ".env", override=True)

    user_data_dir = str(dir_perfil_chrome(project_dir, perfil_dir))
    _avisar_perfil_realocado(project_dir, user_data_dir)
    os.makedirs(user_data_dir, exist_ok=True)

    _configurar_download(user_data_dir)
    # O PFX é reempacotado em AES ANTES de montar os kwargs: o OpenSSL 3 do
    # Node recusa as cifras legadas da AC brasileira e derruba o lançamento —
    # ver `_pkcs12_moderno`. Não convertendo, segue o caminho original.
    pfx_convertido = (_pkcs12_moderno(cert_pfx_path, cert_pfx_passphrase)
                      if cert_pfx_path else None)
    launch_kwargs = _montar_launch_kwargs(
        user_data_dir,
        cert_pfx_path=cert_pfx_path,
        cert_pfx_passphrase=cert_pfx_passphrase,
        cert_subject_cn=cert_subject_cn,
        cert_pfx_bytes=pfx_convertido,
    )
    # Só o MODO, nunca o valor: caminho do .pfx, senha, CN e serial não vão para o log.
    print("[cert] Modo PFX explicito." if cert_pfx_path is not None
          else "[cert] Modo Windows Certificate Store.")
    if cert_pfx_path is not None:
        print("[cert] PKCS#12 reempacotado em AES-256 para o lancamento."
              if pfx_convertido else
              "[cert] PKCS#12 entregue como esta (sem reempacotar).")

    # Quem LANCA fecha. Ponto unico: antes, cada caminho de falha decidia por si
    # se fechava, e alguns nao fechavam — o Chrome ficava vivo segurando o
    # diretorio de perfil, e quem tentasse remover o temporario depois batia em
    # PermissionError no Windows.
    #
    # O laco existe por um caso so: o bloqueio por acesso automatizado. Ele
    # condena a JANELA, entao a saida e trocar de janela — fechar esta e abrir
    # outra ate o portal deixar entrar. Toda outra falha sai na primeira volta,
    # e o `raise`/`return` de cada caminho garante isso.
    def _abortar_se_pedido() -> None:
        if cancelado is not None and cancelado():
            raise LoginCancelado()

    for tentativa in range(1, TENTATIVAS_ACESSO_BLOQUEADO + 1):
        # Antes de LANCAR, nao depois: abrir um Chrome para descartar em
        # seguida e o que fazia o pedido de parada parecer ignorado.
        _abortar_se_pedido()
        p = sync_playwright().start()
        print("Lancando Chrome...")
        try:
            context = p.chromium.launch_persistent_context(**launch_kwargs)
        except BaseException:
            # O LANCAMENTO FALHA, E O DRIVER JA ESTA DE PE. Este `start()` sobe
            # um processo Node, e sem este `stop()` ele sobrevivia a cada falha
            # de lancamento — certificado que o OpenSSL recusa, Chrome ausente,
            # perfil em uso. Cinco execucoes assim em 27/10/2026 deixaram cinco
            # drivers orfaos na maquina. `sair=False`: nao ha sessao no eCAC
            # para encerrar, nao ha nem navegador.
            encerrar_sessao(p, None, sair=False)
            raise
        print("Chrome lancado.")

        page = context.pages[0] if context.pages else context.new_page()
        print("Pagina obtida.")

        try:
            ok = garantir_acesso_ecac(page, cnpj, metrics=metrics,
                                      policy_ok=policy_ok, cert_serial=cert_serial)
        except AcessoBloqueado:
            # Fechar ANTES de decidir: o Chrome bloqueado nao serve nem para a
            # proxima tentativa nem para quem receber a excecao.
            encerrar_sessao(p, context)
            if tentativa == TENTATIVAS_ACESSO_BLOQUEADO:
                print(f"  -> acesso bloqueado em {tentativa} aberturas de "
                      f"navegador seguidas. Desistindo.")
                raise
            print(f"  -> acesso bloqueado ({tentativa}/"
                  f"{TENTATIVAS_ACESSO_BLOQUEADO}). Reabrindo o navegador em "
                  f"{ESPERA_ACESSO_BLOQUEADO_S}s...")
            # De segundo em segundo, para a espera nao virar mais um trecho
            # em que o botao de parar nao tem efeito.
            for _ in range(ESPERA_ACESSO_BLOQUEADO_S):
                _abortar_se_pedido()
                time.sleep(1)
            continue
        except BaseException:
            encerrar_sessao(p, context)
            raise
        if not ok:
            encerrar_sessao(p, context)
            return None
        return p, context, page


# A home do eCAC e o texto do botao de saida. O botao e um
# `<span class="botaoAzul">Sair com Seguranca </span>` — sem id, com espaco
# sobrando no fim —, e so existe no portal: no PER/DCOMP Web ele nao esta.
URL_HOME_ECAC = "https://cav.receita.fazenda.gov.br/ecac/#"
TEXTO_SAIR_COM_SEGURANCA = "Sair com Segurança"
ESPERA_SAIR_MS = 8_000
DOMINIO_DO_ECAC = "cav.receita.fazenda.gov.br"


def _no_dominio_do_ecac(page) -> bool:
    """A pagina esta em algum lugar do eCAC (portal ou PER/DCOMP Web)?

    E a guarda que evita pagar a saida quando nunca se entrou: login que morreu
    no gov.br para numa URL de `sso.acesso.gov.br`, onde nao ha sessao para
    encerrar nem botao para clicar.
    """
    try:
        return DOMINIO_DO_ECAC in (page.url or "")
    except Exception:
        return False


def _clicar_sair(page, espera_ms: int) -> bool:
    """Clica no "Sair com Seguranca" se ele estiver na tela. Nao navega."""
    vias = (
        lambda: page.get_by_text(TEXTO_SAIR_COM_SEGURANCA).first,
        lambda: page.locator(
            f'span.botaoAzul:has-text("{TEXTO_SAIR_COM_SEGURANCA}")').first,
        lambda: page.locator(f'text="{TEXTO_SAIR_COM_SEGURANCA}"').first,
    )
    for localizar in vias:
        try:
            alvo = localizar()
            alvo.wait_for(state="visible", timeout=espera_ms)
            alvo.click(timeout=5_000)
            return True
        except Exception:
            continue
    # Ultimo recurso, pelo DOM: nao depende de ponteiro e passa com veu na
    # frente. O `onclick` do span foi compilado pela pagina e roda no contexto
    # dela, como no `_abrir_popup_de_perfil`.
    try:
        clicou = page.evaluate(
            "(t) => { const e = [...document.querySelectorAll('span, a, button')]"
            ".find(x => (x.textContent || '').includes(t));"
            " if (e) { e.click(); return true; } return false; }",
            TEXTO_SAIR_COM_SEGURANCA)
        return bool(clicou)
    except Exception:
        return False


def sair_com_seguranca(page, espera_ms: int = None) -> bool:
    """Sai do eCAC pelo "Sair com Seguranca". True quando o clique saiu.

    POR QUE SEMPRE, E ANTES DE FECHAR O NAVEGADOR. O certificado tem um numero
    LIMITADO de perfis logados ao mesmo tempo, e fechar o Chrome nao encerra a
    sessao do lado da Receita: o perfil continua OCUPADO ate expirar sozinho.
    Em poucas execucoes nao ha mais vaga, e o relato do operador e sempre o
    mesmo — "nao entra mais". Sair e o que devolve a vaga.

    NAO ESTANDO VISIVEL, VOLTA PARA A HOME e procura de novo, e este e o caminho
    NORMAL: a automacao termina no PER/DCOMP Web
    (`www3.cav.receita.fazenda.gov.br/perdcomp-web`), onde o botao nao existe.

    Nada aqui sobe: a saida e a ultima coisa que se faz com a sessao, e falhar
    nela nao pode virar exceção em cima de um trabalho que ja acabou. O
    desfecho vai para o log, porque "saiu" e "nao saiu" tem consequencias
    diferentes na proxima execucao.
    """
    espera_ms = ESPERA_SAIR_MS if espera_ms is None else espera_ms
    if _clicar_sair(page, espera_ms):
        print("[sair] 'Sair com Seguranca' clicado.")
        return True

    print("[sair] botao fora da tela (PER/DCOMP Web?); voltando para a home do eCAC...")
    try:
        page.goto(URL_HOME_ECAC, wait_until="domcontentloaded", timeout=30_000)
    except Exception as e:  # noqa: BLE001 — sem home nao ha botao, e e so isso
        print(f"[sair] a home do eCAC nao abriu ({type(e).__name__}); "
              "a sessao vai expirar sozinha.")
        return False

    if _clicar_sair(page, espera_ms):
        print("[sair] 'Sair com Seguranca' clicado (depois de voltar para a home).")
        return True
    print("[sair] 'Sair com Seguranca' nao foi encontrado nem na home. "
          "A sessao vai ficar ocupada ate expirar.")
    return False


def encerrar_sessao(p=None, context=None, *, sair: bool = True) -> None:
    """Fecha contexto e para o Playwright. IDEMPOTENTE e sem levantar.

    Chamar duas vezes nao pode virar erro: o teardown da execucao e o caminho
    de falha de quem lancou podem alcancar a mesma sessao.

    SAI DO ECAC ANTES DE FECHAR, e por isso a saida vive AQUI: este e o funil
    por onde todo encerramento passa — o fim normal, o caminho de falha de
    `main` e o teardown de quem chamou. Pendurar a saida em cada um deles seria
    garantir que um ficasse de fora, e um que fica de fora e um perfil ocupado.

    So tenta quando a pagina esta no dominio do eCAC: login que morreu no
    gov.br nao tem sessao para encerrar, e `sair=False` existe para quem sabe
    que nao ha (teste, ou sessao que o portal ja encerrou).
    """
    if sair and context is not None:
        for pagina in _paginas_do_contexto(context):
            if not _no_dominio_do_ecac(pagina):
                continue
            try:
                if sair_com_seguranca(pagina):
                    break
            except Exception:  # noqa: BLE001 — a saida nunca derruba o fechamento
                pass
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


def _paginas_do_contexto(context) -> list:
    """As abas vivas do contexto. Lista vazia quando nao da para olhar."""
    try:
        return [pg for pg in context.pages if not pg.is_closed()]
    except Exception:
        return []


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


def _acesso_bloqueado(page) -> bool:
    """A pagina esta exibindo o bloqueio por "acesso automatizado"?

    O aviso vem dentro de um `div.login-caixa-erros-validacao`, mas quem decide
    aqui e o TEXTO. Aquela caixa e a de erros de validacao do login em geral —
    serve tambem para certificado recusado e afins — entao casar pela classe
    trataria qualquer recusa como bloqueio. E a resposta a um bloqueio, jogar o
    Chrome fora e abrir outro, e cara demais para ser dada por engano.
    """
    return MENSAGEM_ACESSO_BLOQUEADO in _conteudo(page)


def garantir_acesso_ecac(page, cnpj: str, *, metrics=None,
                         policy_ok: bool = True, cert_serial: str = "",
                         insistencias_acesso_automatizado: int | None = None) -> bool:
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

    `insistencias_acesso_automatizado`: quantas vezes esperar e reenviar quando a
    troca e recusada como "acesso automatizado" (padrao:
    `INSISTENCIAS_ACESSO_AUTOMATIZADO_NA_TROCA`; 0 devolve False na primeira,
    como antes).
    """
    if insistencias_acesso_automatizado is None:
        insistencias_acesso_automatizado = INSISTENCIAS_ACESSO_AUTOMATIZADO_NA_TROCA

    _ULTIMA_RECUSA["mensagem"] = ""
    _CHEGOU_NA_TROCA["sim"] = False

    def _captcha_fn(chamadas: int, resolvido: bool, rodadas: int) -> None:
        if metrics:
            metrics.registrar_captcha(chamadas, resolvido, rodadas)

    def _ja_logado():
        return "cav.receita.fazenda.gov.br/ecac" in page.url and "autenticacao" not in page.url

    def _dashboard_na_tela(timeout_ms: int = 5_000) -> bool:
        """O dashboard do eCAC esta visivel — prova de login que a URL nao da.

        `_ja_logado` le a URL, e a URL mente nos instantes em que o gov.br ainda
        esta redirecionando: o login ja valeu, o dashboard ja desenhou, e a barra
        de enderecos ainda mostra um passo intermediario da autenticacao.

        Foi o que derrubou a linha 4 em producao (27/08/2026, 10:23): o captcha
        pos-certificado foi resolvido, o botao "Seu certificado digital" sumiu da
        tela — porque o login TINHA dado certo — e a automacao leu o sumico do
        botao como fracasso e abortou a empresa.

        So e chamada nos caminhos de desistencia, entao os 5s nao entram no custo
        de nenhuma execucao que esta indo bem.
        """
        try:
            page.locator("#btnPerfil").first.wait_for(state="visible",
                                                      timeout=timeout_ms)
            return True
        except Exception:
            return False

    def _autenticado() -> bool:
        """Login confirmado pela URL ou pelo dashboard, o que aparecer primeiro."""
        return _ja_logado() or _dashboard_na_tela()

    print("Abrindo o eCAC ...")
    try:
        page.goto(ECAC_URL, wait_until="commit", timeout=30_000)
        print("  -> pagina inicial carregada.")
    except Exception as e:
        # Rede fora e falha da empresa nao podem terminar igual. Devolver False
        # aqui manda a empresa embora como "nao tentada" e libera a proxima da
        # fila para bater no mesmo muro — foi assim que uma queda de tres
        # minutos consumiu cinco empresas de uma vez. `PortalIndisponivel` sobe
        # para quem sabe esperar.
        if _falha_de_rede(e):
            print(f"  -> o portal nao respondeu ({type(e).__name__}); "
                  "isso e a REDE, nao esta empresa.")
            raise PortalIndisponivel(str(e)) from e
        print(f"  -> erro no goto: {type(e).__name__}")
        return False

    page.wait_for_timeout(1_500)

    # Tela de erro do portal: recarregar ANTES de decidir qualquer coisa.
    #
    # O lugar importa. Em 03/09/2026 o log dizia "URL indica eCAC mas dashboard
    # nao carregou" — a URL era do eCAC, ou seja a SESSAO existia; o que nao
    # havia era pagina, porque o portal tinha servido a tela de erro dele. Tudo
    # o que vem abaixo (o bloqueio, a sessao ativa, o botao do gov.br) le a tela
    # para decidir, e nenhuma dessas leituras significa coisa alguma numa tela
    # de erro. Recarregando aqui, todas passam a ler a pagina de verdade — e a
    # sessao que voltar e aproveitada em vez de virar um login novo.
    erro_inicial = _erro_do_ecac(page)
    if erro_inicial:
        print(f"  -> o e-CAC devolveu uma pagina de erro: {erro_inicial}")
        print("  -> recarregando a home antes de seguir...")
        try:
            page.goto(ECAC_URL, wait_until="commit", timeout=30_000)
            page.wait_for_timeout(1_500)
        except Exception as e:
            print(f"  -> a recarga nao completou ({type(e).__name__}).")

    print("Verificando bloqueio de acesso automatizado...")
    if _acesso_bloqueado(page):
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
        loc_govbr, sel_govbr = _procurar_govbr(page)
        if loc_govbr is None:
            # O botao pode faltar por duas razoes muito diferentes, e ate
            # 03/09/2026 as duas saiam com a mesma frase — que mandava procurar
            # problema no seletor quando nao havia nenhum.
            #
            # Aqui e so o RELATO: a recarga ja foi tentada logo depois do goto,
            # e repeti-la custaria outra varredura de 15s para reencontrar a
            # mesma tela. Quem insiste de verdade e quem chamou — para ele, este
            # False significa "o portal esta fora, tente esta empresa de novo".
            erro = _erro_do_ecac(page)
            if erro:
                print(f"  -> o e-CAC segue na pagina de erro: {erro}")
                registrar_erro(f"Login: e-CAC devolveu pagina de erro ({erro}).")
                return False
            print("  -> botao 'Entrar com gov.br' nao encontrado.")
            registrar_erro("Login: botao 'Entrar com gov.br' nao encontrado.")
            return False

        # Duas esperas, e elas respondem a coisas diferentes: o documento ter
        # terminado de carregar, e a pagina ter carregado QUEM ATENDE o clique.
        _pagina_pronta(page)
        _pronto_para_govbr(page)

        # Segunda conferencia, agora COLADA no clique. A primeira foi logo
        # depois do `goto`, e o bloqueio nao chega so na abertura: ele aparece
        # tambem enquanto a tela de login se monta, depois do "Voltar para a
        # pagina de login" e durante as duas esperas acima. Clicar com o aviso
        # ja na tela gasta o captcha e o certificado para terminar em recusa.
        if _acesso_bloqueado(page):
            registrar_erro("Login: acesso bloqueado — aviso de acesso automatizado "
                           "antes do clique em 'Entrar com gov.br'.")
            print("  -> [BLOQUEADO] aviso de acesso automatizado na tela de login. "
                  "Sinalizando reinicio...")
            raise AcessoBloqueado()

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

        # O solver devolve assim que resolve o desafio; a navegacao que o submit
        # dispara vem DEPOIS. Sem deixar a pagina assentar, a leitura abaixo
        # cairia no documento anterior — o de antes do submit — e nao veria
        # aviso nenhum. Mesma dose e mesma ordem usadas na guarda de
        # dispositivos, logo depois de apresentar o certificado.
        page.wait_for_timeout(2_000)
        _pagina_pronta(page)

        # Terceira conferencia. O captcha e o momento em que o gov.br decide se
        # a sessao parece gente, e a recusa nao chega como captcha errado: chega
        # depois, como este aviso, na tela que o submit carrega. Fica FORA do
        # `if` de cima de proposito — o bloqueio aparece tanto quando o captcha
        # foi resolvido quanto quando ele falhou e a pagina seguiu assim mesmo.
        # Passar batido daqui levaria o certificado a ser apresentado a uma
        # sessao ja condenada, gastando a apresentacao para terminar em recusa.
        if _acesso_bloqueado(page):
            registrar_erro("Login: acesso bloqueado — aviso de acesso automatizado "
                           "apos o captcha do 'Entrar com gov.br'.")
            print("  -> [BLOQUEADO] aviso de acesso automatizado depois do captcha. "
                  "Sinalizando reinicio...")
            raise AcessoBloqueado()

    cert_selectors = [
        "#login-certificate",
        "a:has-text('Seu certificado digital')",
        "button:has-text('Seu certificado digital')",
        "text=Seu certificado digital",
    ]

    def _botao_certificado():
        """(seletor, locator) do primeiro botao de certificado VISIVEL, ou None."""
        for sel in cert_selectors:
            loc = page.locator(sel).first
            if loc.is_visible():
                return sel, loc
        return None

    def _clicar_certificado() -> bool:
        """Espera o botao OU o login ja feito — o que vier primeiro.

        O gov.br as vezes reaproveita a sessao e, depois do captcha, redireciona
        direto para o eCAC: a tela do certificado nunca vem. Esperar so pelo
        botao custava ~22s ate desistir para entao perceber o login (execucao
        real de 09/10/2026, 15:58). O teto e o mesmo de antes (20s no primeiro
        seletor + 2s em cada um dos outros).
        """
        print("Procurando botao 'Seu certificado digital'...")
        achado = []

        def _pronto() -> bool:
            if _ja_logado() or page.locator("#btnPerfil").first.is_visible():
                return True
            botao = _botao_certificado()
            if botao:
                achado.append(botao)
            return bool(botao)

        if _esperar_ate(page, _pronto, ESPERA_BOTAO_CERTIFICADO_MS) and achado:
            sel, loc = achado[-1]
            print(f"  -> match com: {sel}")
            loc.click()
            return True
        if not achado and (_ja_logado() or _dashboard_na_tela(timeout_ms=500)):
            print("  -> a pagina ja foi para o eCAC (sessao do gov.br reaproveitada); "
                  "nao ha botao de certificado a clicar.")
            return False
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
                # O botao some por TRES motivos, e so um deles e defeito:
                #
                #   1. o login ja aconteceu e nao ha mais o que apresentar;
                #   2. o gov.br trocou a tela pela do limite de dispositivos,
                #      que nao tem botao de certificado nenhum;
                #   3. a pagina quebrou de verdade.
                #
                # Sem o caso 2 aqui, uma conta no limite reportava "botao nao
                # encontrado" em toda tentativa — inclusive nas seguintes, ja que
                # o limite persiste — e a automacao chamadora recebia apenas
                # `None`, que ela traduz como "login nao concluido". A causa
                # ficava so neste log, com outro nome de arquivo, e ninguem
                # cruzava os dois.
                if _autenticado():
                    print("  -> botao nao encontrado mas pagina ja esta logada. Continuando.")
                    break
                if MENSAGEM_DISPOSITIVOS_MAXIMOS in _conteudo(page):
                    registrar_erro("Login: numero maximo de dispositivos conectados atingido.")
                    print("  -> [DISPOSITIVOS] a tela do limite substituiu a do certificado.")
                    raise DispositivosMaximo()
                # Botao nao apareceu — pagina do gov.br lenta / captcha ainda
                # assentando (visto em maquina lenta: a MESMA conta logava noutra).
                # Em vez de abortar de primeira, espera e PROCURA de novo (o proximo
                # _clicar_certificado reespera ~20s). NAO recarrega: um reload aqui
                # pode descartar o estado do OAuth do gov.br e transformar um
                # transitorio (botao a um instante de renderizar) em falha certa.
                if tentativa_cert < MAX_TENTATIVAS_CERT:
                    print("  -> botao do certificado nao apareceu; aguardando e "
                          "procurando de novo...")
                    try:
                        page.wait_for_timeout(3_000)
                    except Exception:
                        # pagina caiu de verdade -> aborta com elegancia (como antes)
                        registrar_erro("Login: botao 'Seu certificado digital' nao "
                                       "encontrado (pagina indisponivel).")
                        print("[cert] Pagina indisponivel ao reesperar. Abortando.")
                        return False
                    continue
                registrar_erro("Login: botao 'Seu certificado digital' nao encontrado.")
                print("[cert] Botao nao encontrado apos todas as tentativas. Abortando.")
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

            # Segunda opiniao antes de recarregar: a URL as vezes ainda mostra um
            # passo do gov.br enquanto o dashboard ja esta desenhado. Recarregar
            # nesse instante joga fora um login que deu certo — e foi assim que
            # a tela seguinte apareceu sem o botao do certificado e a empresa foi
            # abortada. Os 5s so sao pagos aqui, onde a alternativa e um reload.
            if _dashboard_na_tela():
                print("  -> login confirmado pelo dashboard (a URL ainda nao "
                      "tinha acompanhado).")
                break

            if tentativa_cert < MAX_TENTATIVAS_CERT:
                print(f"  -> login nao concluido. Recarregando e tentando novamente...")
                page.reload(wait_until="domcontentloaded")
                page.wait_for_timeout(2_000)
            else:
                if _autenticado():
                    print("  -> ultima tentativa mas pagina ja esta logada. Continuando.")
                    break
                registrar_erro("Login: nao concluido apos todas as tentativas com certificado digital.")
                print("[cert] Login nao concluido apos todas as tentativas. Abortando.")
                return False

        print("Captcha pos-certificado tratado.")
        print("  -> captcha tratado; navegacao seguiu.")

        print("Aguardando redirecionamento final para cav.receita.fazenda.gov.br/ecac (ate 90s)...")
        # Em fatias, nao num `wait_for_url` de 90s: aquela espera bloqueia a
        # thread inteira e o botao "Parar" fica sem efeito o tempo todo.
        if _esperar_ate(page, _ja_logado, 90_000):
            print("  -> redirecionamento final concluido.")
        else:
            registrar_erro("Login: redirecionamento final para o eCAC nao ocorreu.")
            print("  -> nao chegou no eCAC no tempo esperado.")
            try:
                shot = str(project_dir / "_debug_pos_cert.png")
                page.screenshot(path=shot, full_page=True)
                print("     screenshot de debug gravado.")
            except Exception:
                pass
            return False

    print("Aguardando dashboard do eCAC carregar (#btnPerfil, ate 60s)...")
    # Idem: fatiado para o "Parar" ter onde acontecer.
    if not _esperar_ate(page,
                        lambda: page.locator("#btnPerfil").first.is_visible(),
                        60_000):
        registrar_erro("Login: dashboard do eCAC nao carregou (#btnPerfil ausente).")
        print("  -> o dashboard nao apareceu no tempo esperado.")
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

    # Popup opcional "Em breve, o acesso ao e-CAC sera desativado": se aparecer,
    # clica em "Continuar no e-CAC por enquanto" e segue o fluxo normalmente; se nao
    # aparecer, apenas segue. NAO retorna (diferente do popup da Caixa Postal, que
    # navega para outra tela): aqui so fechamos o aviso e continuamos para o perfil.
    # Com ESPERA, porque aqui o aviso ainda esta aparecendo e o custo e ruido.
    _fechar_aviso_de_encerramento(page, espera_ms=ESPERA_AVISO_ENCERRAMENTO_MS)

    # O dialogo de perfil ESTEVE ABERTO em algum momento? E o que separa "a troca
    # deu certo" de "o dialogo nunca apareceu" — ver `_popup_fechado_significa`.
    _DIALOGO = {"abriu": False}

    def _abrir_formulario() -> bool:
        """O popup "Alterar perfil de acesso" aberto, na aba PJ, com o campo do
        CNPJ na tela. False quando o formPJ nao aparece. Chamado de novo no
        reenvio do "acesso automatizado" se o eCAC tiver fechado o popup."""
        # Um aviso na frente do dashboard impede o dialogo de abrir, e ele pode
        # chegar depois do login. Olhada de custo zero, a cada tentativa.
        _fechar_aviso_de_encerramento(page)
        print("Clicando em 'Alterar perfil de acesso'...")
        _abrir_popup_de_perfil(page)

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
        try:
            page.locator("#txtNIPapel2").first.wait_for(state="visible", timeout=10_000)
            # O UNICO ponto em que se sabe que o dialogo abriu de verdade. Sem
            # esta marca, "popup fechado" no fim valeria como troca concluida.
            _DIALOGO["abriu"] = True
        except Exception:
            print("  -> input nao ficou visivel; vai tentar fallback via JS.")
        return True

    if not _abrir_formulario():
        return False
    nip_input = page.locator("#txtNIPapel2").first

    # O CNPJ confirmou no campo? So entao "campo vazio" pode querer dizer que a
    # PAGINA o consumiu (ver `_formulario_em_envio`).
    _FORMULARIO = {"preenchido": False}

    def _valor_nipapel() -> str:
        try:
            return page.evaluate(
                "() => { const i = document.getElementById('txtNIPapel2');"
                " return i ? (i.value || '') : ''; }") or ""
        except Exception:
            return ""

    def _garantir_cnpj_preenchido() -> bool:
        """Preenche o CNPJ em #txtNIPapel2 e CONFIRMA que o valor colou.
        O eCAC as vezes recusa com 'CNPJ nao preenchido' quando o valor nao
        registrou no form antes do envio (race). O fill() do Playwright ja dispara
        input; aqui RELEMOS e, SO se nao colou, forcamos via JS (value + input +
        change). Sem 'blur' de proposito: a validacao/onblur do form nao deve ser
        acionada antes de validaCaptcha ficar pronta. A conferencia compara SO OS
        DIGITOS (o campo pode aplicar mascara CNPJ)."""
        alvo = "".join(ch for ch in cnpj if ch.isdigit()) or cnpj

        def _colou() -> bool:
            v = _valor_nipapel()
            if alvo:
                return "".join(ch for ch in v if ch.isdigit()) == alvo
            return bool(v.strip())

        try:
            nip_input.fill(cnpj)
        except Exception:
            pass
        if _colou():
            _FORMULARIO["preenchido"] = True
            return True
        try:
            page.evaluate(
                "(v) => { const i = document.getElementById('txtNIPapel2');"
                " if (i) { i.value = v;"
                " i.dispatchEvent(new Event('input', {bubbles:true}));"
                " i.dispatchEvent(new Event('change', {bubbles:true})); } }",
                cnpj,
            )
        except Exception:
            pass
        ok = _colou()
        _FORMULARIO["preenchido"] = ok
        if not ok:
            print("  -> [AVISO] CNPJ nao confirmou no campo apos preencher.")
        return ok

    print("Preenchendo identificador do perfil PJ em #txtNIPapel2...")
    _garantir_cnpj_preenchido()

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
        """True enquanto o dialogo de perfil estiver na tela.

        Ver o dialogo aberto AQUI tambem marca `_DIALOGO`: o dialogo pode abrir
        depois da espera de `_abrir_formulario` ter estourado, e o que importa
        para o desfecho e ele ter aparecido alguma vez, nao em qual linha.
        """
        for sel in ("#txtNIPapel2", "div.ui-dialog:has(#formPJ)"):
            try:
                if page.locator(sel).first.is_visible(timeout=500):
                    _DIALOGO["abriu"] = True
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

    SEL_BOTAO_ALTERAR = ('#formPJ input[value="Alterar"], '
                         '#formPJ input[onclick*="validaCaptcha"], '
                         '#formPJ input[type="submit"]')

    def _formulario_em_envio() -> bool:
        """A PAGINA ja esta enviando o formulario?

        Os sinais sao os do `[diag]` das trocas que deram certo em producao
        (27/08/2026): o botao "Alterar" some, e o campo do CNPJ e esvaziado — o
        ajax da propria pagina ja levou o envio. A resposta (troca ou recusa) as
        vezes demora mais que a janela de `_enviar_uma_vez` para aparecer, e um
        clique nesse intervalo e o SEGUNDO envio: o que o eCAC marca como acesso
        automatizado. So vale depois que o CNPJ confirmou no campo — antes disso,
        campo vazio e so campo vazio.
        """
        if not _FORMULARIO["preenchido"]:
            return False
        if not _valor_nipapel().strip():
            return True
        try:
            return not page.locator(SEL_BOTAO_ALTERAR).first.is_visible(timeout=300)
        except Exception:
            return False

    def _reacao_da_tela() -> str:
        """O que a tela ja esta dizendo AGORA: "erro", "ok", "enviando" (a pagina
        ja levou o envio) ou "" (nada ainda)."""
        if _mensagem_de_erro():
            return "erro"
        if not _popup_aberto():
            # Fechado SEM nunca ter aberto nao e reacao a envio nenhum: deixa a
            # tentativa seguir e quem decide o desfecho e `_desfecho`.
            estado = _popup_fechado_significa(_DIALOGO["abriu"])
            return estado if estado == "ok" else ""
        if _formulario_em_envio():
            return "enviando"
        return ""

    def _clicar_no_alterar() -> None:
        try:
            page.locator(SEL_BOTAO_ALTERAR).first.click(timeout=5_000)
            print("  -> [via=clique] clicado (uma vez).")
        except Exception as e:
            print(f"  -> [via=clique] o clique nao confirmou ({type(e).__name__}); "
                  "deixando a tela decidir.")

    _ENVIOS = {"n": 0}

    def _clicar_alterar() -> str:
        _ENVIOS["n"] += 1
        print(f"Enviando o 'Alterar' (formPJ) — envio {_ENVIOS['n']}...")
        return _enviar_uma_vez(_reacao_da_tela, _clicar_no_alterar,
                               page.wait_for_timeout)

    def _preparar_reenvio(motivo: str) -> None:
        """A tela pronta para mais um envio.

        Limpa a recusa velha ANTES: senao `_reacao_da_tela` e `_desfecho` leem a
        .mensagemErro anterior, `_enviar_uma_vez` conclui "a pagina ja reagiu" e
        NAO envia — o reenvio viraria no-op. So a recusa DO MOTIVO e limpa: uma
        outra, concorrente (procuracao), fica visivel e continua sendo
        respeitada. Se o eCAC fechou o popup, ele e aberto de novo; o CNPJ e
        repreenchido (e o `fill` pode, ele mesmo, levar o envio pela pagina).
        """
        marca = {"cnpj_nao_preenchido": "preenchido",
                 "acesso_automatizado": "acesso automatizado"}.get(motivo)
        if marca:
            try:
                page.evaluate(
                    "(m) => document.querySelectorAll('.mensagemErro').forEach(e => {"
                    " const t = (e.textContent || '').toLowerCase();"
                    " if (t.includes(m)) { e.textContent = ''; e.style.display = 'none'; } })",
                    marca)
            except Exception:
                pass
        if not _popup_aberto():
            print("  -> o popup de perfil fechou; abrindo de novo na mesma janela...")
            _abrir_formulario()
        _garantir_cnpj_preenchido()
        page.wait_for_timeout(600)

    def _esperar_s(segundos: float) -> None:
        """Espera em fatias de 1s, obedecendo o "Parar"."""
        for _ in range(int(segundos)):
            _checkpoint()
            page.wait_for_timeout(1_000)

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
                return _popup_fechado_significa(_DIALOGO["abriu"]), ""
            fechado_antes = fechado
            if time.monotonic() >= limite:
                return "timeout", ""
            try:
                page.wait_for_timeout(400)
            except Exception:
                return "timeout", ""

    # Ate o eCAC responder de vez — ver `_enviar_ate_o_desfecho`. Cada envio e UM
    # so (a pagina, ou um clique se ela nao enviar). "Acesso automatizado" espera
    # e reenvia NA MESMA janela; "CNPJ nao preenchido" e tela muda, um reenvio;
    # as demais recusas (procuracao, CNPJ invalido) encerram na hora.
    #
    # Daqui em diante a falha e DESTA empresa: o CNPJ ja esta no campo.
    _CHEGOU_NA_TROCA["sim"] = True
    estado, erro, via = _enviar_ate_o_desfecho(
        _clicar_alterar, _desfecho, _preparar_reenvio, _esperar_s,
        insistencias=insistencias_acesso_automatizado)

    if estado == "erro":
        registrar_erro(erro)
        # O `via=` sai junto com a recusa de proposito: e o par
        # (quem enviou, o que o portal respondeu) que confirma ou derruba a
        # hipotese de `_enviar_uma_vez` na proxima execucao real.
        print(f"  -> [RECUSADO pelo eCAC | via={via}] {erro}")
        # Guardado ANTES de fechar: o popup leva a mensagem embora.
        _ULTIMA_RECUSA["mensagem"] = erro
        _fechar_popup()
        return False

    if estado == "nao_abriu":
        # Dito com as palavras do que aconteceu, e nao com as do caso vizinho: o
        # popup nao "continuou na tela", ele NUNCA apareceu. Quem le isso vai
        # procurar o que estava na frente do dashboard, que e onde esta a causa.
        print("  -> o popup de perfil NUNCA apareceu: a troca nao aconteceu.")
        registrar_erro(
            "Troca de perfil nao aconteceu: o dialogo do formPJ nunca ficou "
            "visivel. Costuma ser um aviso do e-CAC na frente do dashboard.")
        _fechar_popup()
        return False

    if estado != "ok":
        print("  -> popup NAO fechou: a troca de perfil nao se confirmou.")
        registrar_erro("Troca de perfil nao confirmada: o popup do formPJ "
                       "continuou na tela apos o envio.")
        _fechar_popup()
        return False

    try:
        page.wait_for_load_state("domcontentloaded", timeout=15_000)
    except Exception:
        pass
    print(f"  -> perfil de acesso alterado (via={via}).")
    print("Concluido.")
    return True
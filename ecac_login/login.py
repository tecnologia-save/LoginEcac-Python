"""Login no eCAC via Patchright com client_certificates.

Uso:
    from ecac_login import fazer_login
    p, context, page = fazer_login(cnpj="12345678000195")

Pre-requisitos no .env do projeto chamador:
    CERT_PFX_PATH=C:\\Certificados\\meu_certificado.pfx
    CERT_PFX_PASSPHRASE=senha-do-pfx
    GEMINI_API_KEY=chave-gemini
"""
import json
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from patchright.sync_api import sync_playwright

from resolvedor_captcha import solve_hcaptcha
from .log_manager import registrar_erro

ECAC_URL = "http://cav.receita.fazenda.gov.br/ecac/Default.aspx"

MENSAGEM_ACESSO_BLOQUEADO = (
    "Prezado usuário, o seu acesso foi bloqueado por possuir atributos "
    "que o caracteriza como um acesso automatizado."
)


class AcessoBloqueado(Exception):
    pass

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

    prefs_file.write_text(json.dumps(prefs), encoding="utf-8")
    print(f"[download] Diretorio configurado: {downloads_dir}")


def _build_client_certificates(project_dir: Path):
    load_dotenv(dotenv_path=project_dir / ".env", override=True)
    cert_path = os.environ.get("CERT_PFX_PATH")
    cert_pass = os.environ.get("CERT_PFX_PASSPHRASE")
    if not cert_path or not cert_pass:
        print("[cert] CERT_PFX_PATH ou CERT_PFX_PASSPHRASE ausente no .env.")
        return None
    if not os.path.isfile(cert_path):
        print(f"[cert] Arquivo nao encontrado: {cert_path}")
        return None
    print(f"[cert] Configurando cert .pfx: {cert_path}")
    return [
        {"origin": origin, "pfxPath": cert_path, "passphrase": cert_pass}
        for origin in CERT_ORIGINS
    ]


def _try_solve_captcha(page, etapa: str, max_attempts: int = 3) -> bool:
    print(f"[{etapa}] Verificando hCaptcha (ate {max_attempts} tentativas)...")
    for tentativa in range(1, max_attempts + 1):
        try:
            resultado = solve_hcaptcha(page, log_fn=registrar_erro)
            if resultado:
                print(f"[{etapa}] tentativa {tentativa}/{max_attempts}: OK (resolvido ou ausente).")
                return True
            print(f"[{etapa}] tentativa {tentativa}/{max_attempts}: solver retornou False.")
        except Exception as e:
            print(f"[{etapa}] tentativa {tentativa}/{max_attempts}: {type(e).__name__}: {e}")
        page.wait_for_timeout(2_000)
    return False


def main(cnpj: str, project_dir: Path | str = None):
    """Realiza o login no eCAC e retorna (playwright, context, page) autenticados.

    Args:
        cnpj: CNPJ da empresa (14 digitos, sem formatacao).
        project_dir: Diretorio do projeto chamador. Usado para salvar o perfil do Chrome
                     e screenshots de debug. Padrao: diretorio de trabalho atual.

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
    client_certs = _build_client_certificates(project_dir)

    launch_kwargs = dict(
        user_data_dir=user_data_dir,
        channel="chrome",
        headless=False,
        no_viewport=True,
        ignore_https_errors=True,
        accept_downloads=True,
        args=["--start-maximized", "--remote-debugging-port=9222"],
    )
    if client_certs:
        launch_kwargs["client_certificates"] = client_certs

    p = sync_playwright().start()
    print("Lancando Chrome...")
    context = p.chromium.launch_persistent_context(**launch_kwargs)
    print("Chrome lancado.")

    _downloads_dir = Path.home() / "Downloads"

    def _salvar_download(download):
        import shutil
        import time as _time
        nome = download.suggested_filename or f"download_{int(_time.time())}"
        destino = _downloads_dir / nome
        try:
            temp = download.path()  # bloqueia ate o download completar
            if temp and Path(temp).exists():
                shutil.copy2(temp, str(destino))
                print(f"[download] Salvo em: {destino}")
            else:
                print(f"[download] Caminho temporario invalido para '{nome}': {temp}")
        except Exception as e:
            print(f"[download] Erro ao salvar '{nome}': {type(e).__name__}: {e}")

    context.on("download", _salvar_download)

    page = context.pages[0] if context.pages else context.new_page()
    print("Pagina obtida.")

    def _ja_logado():
        return "cav.receita.fazenda.gov.br/ecac" in page.url and "autenticacao" not in page.url

    print(f"Abrindo {ECAC_URL} ...")
    try:
        page.goto(ECAC_URL, wait_until="commit", timeout=30_000)
        print(f"  -> URL: {page.url}")
    except Exception as e:
        print(f"  -> erro no goto: {type(e).__name__}: {e}")
        input("ENTER pra encerrar...")
        return None

    page.wait_for_timeout(1_500)
    print("Verificando bloqueio de acesso automatizado...")
    if MENSAGEM_ACESSO_BLOQUEADO in page.content():
        registrar_erro("Login: acesso bloqueado — pagina exibiu mensagem de acesso automatizado.")
        print("  -> [BLOQUEADO] Acesso bloqueado. Fechando navegador e sinalizando reinicio...")
        try:
            context.close()
        except Exception:
            pass
        try:
            p.stop()
        except Exception:
            pass
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
                print(f"  -> URL apos voltar: {page.url}")
        except Exception:
            pass

        print("Clicando em 'Entrar com gov.br'...")
        gov_btn = page.locator('xpath=//*[@id="login-dados-certificado"]/p[2]/input').first
        try:
            gov_btn.wait_for(state="visible", timeout=15_000)
            gov_btn.click()
        except Exception as e:
            print(f"  -> botao nao encontrado: {type(e).__name__}: {e}")
            input("ENTER pra encerrar...")
            return None

        print("  -> clicado.")

        if not _try_solve_captcha(page, "captcha-pos-govbr"):
            if _ja_logado():
                print("  -> captcha falhou mas pagina ja esta logada. Continuando.")
            else:
                registrar_erro("Login: hCaptcha nao resolvido apos 3 tentativas (etapa gov.br).")
                print("[captcha] 3 tentativas falharam. Abortando.")
                return None

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
                return None

            print("  -> clicado. Aguardando recarregar...")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=20_000)
            except Exception:
                pass
            page.wait_for_timeout(2_000)
            print(f"  -> URL apos cert: {page.url}")

            if _ja_logado():
                print("  -> login realizado sem captcha.")
                break

            print("  -> verificando captcha pos-certificado...")
            if not _try_solve_captcha(page, f"captcha-pos-cert-t{tentativa_cert}"):
                print(f"[captcha] tentativa {tentativa_cert}: falhou ao resolver captcha.")

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
                return None

        print("Captcha pos-certificado tratado.")
        print(f"  -> URL apos captcha: {page.url}")

        print("Aguardando redirecionamento final para cav.receita.fazenda.gov.br/ecac (ate 90s)...")
        try:
            page.wait_for_url(
                lambda u: "cav.receita.fazenda.gov.br/ecac" in u and "autenticacao" not in u,
                timeout=90_000,
            )
            print(f"  -> URL: {page.url}")
        except Exception as e:
            registrar_erro(f"Login: redirecionamento para eCAC nao ocorreu. URL atual: {page.url}")
            print(f"  -> nao chegou no eCAC: {type(e).__name__}: {e}")
            try:
                shot = str(project_dir / "_debug_pos_cert.png")
                page.screenshot(path=shot, full_page=True)
                print(f"     screenshot: {shot}")
            except Exception:
                pass
            return None

    print("Aguardando dashboard do eCAC carregar (#btnPerfil, ate 60s)...")
    try:
        page.locator("#btnPerfil").first.wait_for(state="visible", timeout=60_000)
    except Exception as e:
        registrar_erro(f"Login: dashboard do eCAC nao carregou (#btnPerfil ausente). URL: {page.url}")
        print(f"  -> erro aguardando dashboard: {type(e).__name__}: {e}")
        try:
            shot = str(project_dir / "_debug_dashboard.png")
            page.screenshot(path=shot, full_page=True)
            print(f"     screenshot: {shot}")
        except Exception:
            pass
        return None

    page.wait_for_timeout(3_000)

    print("Clicando em 'Alterar perfil de acesso'...")
    page.locator("#btnPerfil").first.click()

    print("Aguardando popup carregar (formPJ no DOM)...")
    try:
        page.locator("#formPJ").first.wait_for(state="attached", timeout=15_000)
    except Exception:
        print("  -> #formPJ nao aparece. Abortando.")
        return None

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

    print(f"Preenchendo CNPJ '{cnpj}' em #txtNIPapel2...")
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
                return Array.from(f.querySelectorAll('input')).map((i, idx) => ({
                    idx, type: i.type, value: i.value, name: i.name, id: i.id,
                    visible: i.offsetParent !== null,
                    onclick: i.getAttribute('onclick'),
                }));
            }"""
        )
        print(f"[diag] inputs do formPJ: {inputs_info}")
    except Exception as e:
        print(f"[diag] erro: {e}")

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
        return None

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
            print(f"  -> DOM click resultado: {result}")
        except Exception as e3:
            print(f"  -> falhou tudo: {type(e3).__name__}: {e3}")

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
                registrar_erro(f"[CNPJ: {cnpj}] Acesso automatizado detectado: limite de {MAX_TENTATIVAS_ALTERAR} tentativas atingido.")
                print("  -> Limite de tentativas atingido para erro de acesso automatizado. Abortando.")
                _fechar_popup_e_sair()
                return None
            continue

        if erro:
            registrar_erro(f"[CNPJ: {cnpj}] {erro}")
            _fechar_popup_e_sair()
            return None

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
    print(f"  -> URL apos alteracao: {page.url}")
    print("Concluido.")
    return p, context, page
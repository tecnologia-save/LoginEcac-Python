"""A tela de erro do eCAC nao pode passar por "botao nao encontrado".

Producao, 03/09/2026. Duas empresas seguidas sairam assim, em 35 segundos:

    -> URL indica eCAC mas dashboard nao carregou. Prosseguindo com login normal.
    Clicando em 'Entrar com gov.br'...
      -> botao 'Entrar com gov.br' nao encontrado.

A terceira, no mesmo minuto e no mesmo certificado, logou sem problema. O que
estava na tela nao era um seletor quebrado; era o portal:

    e-CAC  Ocorreu um erro. (Código: 0)  Erro desconhecido.
    Retornar para a página inicial do e-CAC.

e, no outro despejo daquela manha, o proprio eCAC pedindo a repeticao:

    Prezado Usuário, não foi possível validar os seus dados nas bases
    cadastrais da Receita Federal. Por favor, tente mais tarde.

Duas coisas erradas de uma vez: a automacao desistia de uma tela que so pedia
outra tentativa, e o log mandava quem fosse investigar procurar problema no
seletor — onde nao havia nenhum.

As paginas servidas aqui sao os despejos REAIS daquela manha, copiados sem
edicao. Nenhum CNPJ, nome ou token aparece neles (conferido).
"""
import functools
import http.server
import sys
import threading
import time
from pathlib import Path

AQUI = Path(__file__).parent
sys.path.insert(0, str(AQUI.parent))

from patchright.sync_api import sync_playwright

from ecac_login.login import _achar_govbr, _erro_do_ecac, _procurar_govbr

falhas = []


def check(nome, cond, detalhe=""):
    print(f"  {'OK   ' if cond else 'FALHA'} {nome}" + (f"  [{detalhe}]" if detalhe else ""))
    if not cond:
        falhas.append(nome)


SERV = AQUI / "_paginas_erro_ecac"
SERV.mkdir(exist_ok=True)

# Os despejos de producao, guardados aqui de proposito: sao a unica prova do
# que o portal serve nessas horas, e reproduzir de memoria seria testar a
# memoria. Vieram de `logs/_debug_sair_100553.html` e `_debug_sair_095920.html`
# da execucao de 03/09/2026, copiados sem edicao.
#
#   erro_codigo_0.html        -> "Ocorreu um erro. (Código: 0)"
#   erro_bases_cadastrais.html-> "nao foi possivel validar os seus dados..."
#
# A tela de login de verdade, com o botao que a automacao procura.
(SERV / "login.html").write_text(
    '<!DOCTYPE html><html><head><meta charset="utf-8"><title>eCAC</title></head>'
    '<body><h1>e-CAC</h1>'
    # O markup do portal: o gov.br e um <input type="image"> dentro do
    # #login-dados-certificado, e e por ai que SEL_GOVBR o encontra.
    '<div id="login-dados-certificado"><p>Escolha como entrar</p>'
    '<p><input type="image" alt="Entrar com gov.br" src="data:," '
    'onclick="validarHcaptcha()"></p></div>'
    '</body></html>', encoding="utf-8")

Handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(SERV))
Handler.log_message = lambda *a, **k: None
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    page = browser.new_page()

    print()
    print("=== A TELA DE ERRO E RECONHECIDA COMO TAL ===")
    page.goto(BASE + "/erro_codigo_0.html")
    frase = _erro_do_ecac(page)
    check("reconhecida", bool(frase), repr(frase))
    check("com a frase do portal, nao um rotulo generico",
          "ocorreu um erro" in frase.lower(), frase)
    check("e curta o bastante para caber no log", len(frase) <= 200, str(len(frase)))

    page.goto(BASE + "/erro_bases_cadastrais.html")
    frase = _erro_do_ecac(page)
    check("a outra tambem", "validar os seus dados" in frase.lower(), repr(frase))

    print()
    print("=== E A TELA DE LOGIN NAO E CONFUNDIDA COM ERRO ===")
    # O falso positivo aqui seria caro do outro jeito: a automacao passaria a
    # dizer "pagina de erro" e a insistir em toda empresa que loga normalmente.
    page.goto(BASE + "/login.html")
    check("login limpo nao vira 'erro'", _erro_do_ecac(page) == "",
          repr(_erro_do_ecac(page)))

    print()
    print("=== NA TELA DE ERRO NAO HA BOTAO — E ISSO NAO E BUG DE SELETOR ===")
    page.goto(BASE + "/erro_codigo_0.html")
    loc, _ = _achar_govbr(page)
    check("nenhum botao gov.br na tela de erro", loc is None)

    print()
    print("=== IR PARA A HOME RESOLVE, QUE E O QUE A RECUPERACAO FAZ ===")
    # Recarregar a home era tudo o que faltava: a terceira empresa daquela
    # manha provou isso ao logar no mesmo minuto.
    page.goto(BASE + "/login.html")
    loc, sel = _procurar_govbr(page, segundos=5.0)
    check("na home o botao esta la", loc is not None, sel)

    print()
    print("=== A BUSCA NAO PODE VIRAR UMA ESPERA CARA ===")
    page.goto(BASE + "/login.html")
    t0 = time.monotonic()
    _procurar_govbr(page, segundos=15.0)
    achado = time.monotonic() - t0
    check("acha na hora quando o botao esta la", achado < 2.0, f"{achado:.1f}s")

    page.goto(BASE + "/erro_codigo_0.html")
    t0 = time.monotonic()
    loc, _ = _procurar_govbr(page, segundos=3.0)
    gasto = time.monotonic() - t0
    check("e respeita o limite quando nao esta", loc is None and gasto < 6.0,
          f"{gasto:.1f}s")

    print()
    print("=== GUIA FECHADA: NAO EXPLODE ===")
    outra = browser.new_page()
    outra.goto(BASE + "/login.html")
    outra.close()
    try:
        check("_erro_do_ecac devolve '' numa guia morta",
              _erro_do_ecac(outra) == "")
    except Exception as e:
        check("_erro_do_ecac devolve '' numa guia morta", False,
              f"{type(e).__name__}: {e}")

    browser.close()
srv.shutdown()

print()
print("=" * 60)
print("RESULTADO:", "TODOS OS CASOS PASSARAM" if not falhas else f"FALHAS ({len(falhas)}): {falhas}")
print("=" * 60)
sys.exit(1 if falhas else 0)

"""Nenhum valor sensivel pode chegar ao stdout — NORMATIVO.

O runtime do AutoHub captura o stdout do processo. Um CNPJ, um caminho de .pfx,
um subject CN ou uma URL com query string impressos aqui viram dado persistido
na plataforma. Por isso a regra nao e "nao imprimir dados sensiveis" no sentido
frouxo: e que o VALOR nao pode existir na saida.

DUAS CAMADAS, porque uma so nao cobre este modulo:

  ESTATICA   varre a AST inteira de `login.py` e reprova qualquer `print` ou
             `registrar_erro` que INTERPOLE um nome proibido. Alcanca o interior
             de `main()`, que nao roda sem Chrome.
  DINAMICA   executa os helpers puros com valores SENTINELA e prova que eles nao
             aparecem no stdout capturado.

LIMITACAO REGISTRADA: o corpo de `main()` e de `abrir_browser_com_certificado`
so executa com navegador real; para eles vale a camada estatica.

Testar ausencia da palavra "CNPJ" nao provaria nada — o que se testa aqui e a
ausencia do VALOR.
"""
import ast
import re
from pathlib import Path

import pytest

from ecac_login import login
from ecac_login.login import _build_auto_select_cert_flag, _montar_launch_kwargs

FONTE = Path(__file__).resolve().parent.parent / "ecac_login" / "login.py"

FUNCOES_DE_SAIDA = {"print", "registrar_erro"}

# Nomes cujo VALOR nunca pode ser interpolado numa mensagem.
NOMES_PROIBIDOS = {
    "cnpj", "cert_serial", "cert_subject_cn", "subject_cn",
    "cert_pfx_path", "cert_pfx_passphrase", "cert_path", "cert_pass",
    "shot", "downloads_dir", "user_data_dir", "project_dir",
    "prefs_file", "ECAC_URL",
}
# Atributos proibidos, na forma `<algo>.<attr>`.
ATRIBUTOS_PROIBIDOS = {"url"}

# Sentinelas: se aparecerem no stdout, houve vazamento.
CNPJ_SENTINELA = "99123456000188"
URL_SENTINELA = "https://exemplo.invalido/callback?state=SEGREDO_TESTE_123"
PFX_SENTINELA = r"C:\SEGREDO_TESTE\empresa\cert.pfx"
CN_SENTINELA = "SEGREDO_TESTE_CN"
SENHA_SENTINELA = "SEGREDO_TESTE_SENHA"


def _chamadas_de_saida(arvore):
    for no in ast.walk(arvore):
        if not isinstance(no, ast.Call):
            continue
        alvo = no.func
        nome = getattr(alvo, "id", None) or getattr(alvo, "attr", None)
        if nome in FUNCOES_DE_SAIDA:
            yield no


def _interpolacoes(chamada):
    """Nomes e atributos interpolados nos argumentos f-string da chamada."""
    for arg in ast.walk(chamada):
        if not isinstance(arg, ast.FormattedValue):
            continue
        for no in ast.walk(arg.value):
            if isinstance(no, ast.Name):
                yield no.id, ast.unparse(arg.value)
            elif isinstance(no, ast.Attribute):
                yield f".{no.attr}", ast.unparse(arg.value)


# ── Camada estatica ──────────────────────────────────────────────────────────

def test_nenhum_log_interpola_valor_sensivel():
    arvore = ast.parse(FONTE.read_text(encoding="utf-8"))
    achados = []
    for chamada in _chamadas_de_saida(arvore):
        for simbolo, trecho in _interpolacoes(chamada):
            proibido = (simbolo in NOMES_PROIBIDOS
                        or simbolo.lstrip(".") in ATRIBUTOS_PROIBIDOS)
            if proibido:
                achados.append(f"linha {chamada.lineno}: {{{trecho}}}")
    assert not achados, "log com valor sensivel:\n  " + "\n  ".join(achados)


def test_a_varredura_estatica_realmente_detecta():
    """Poder discriminante: a checagem acima falharia se o vazamento voltasse."""
    arvore = ast.parse(
        'def f(cnpj, page):\n'
        '    print(f"CNPJ: {cnpj}")\n'
        '    print(f"URL: {page.url}")\n'
    )
    simbolos = {s for c in _chamadas_de_saida(arvore) for s, _ in _interpolacoes(c)}
    assert "cnpj" in simbolos
    assert ".url" in simbolos


def test_nenhum_cnpj_numerico_no_modulo():
    """Nem no docstring: exemplo numerico vira dado plausivel em copia/cola."""
    texto = FONTE.read_text(encoding="utf-8")
    assert not re.search(r"\b\d{11,14}\b", texto)


# ── Camada dinamica: sentinelas nos helpers puros ────────────────────────────

def test_montar_launch_kwargs_nao_imprime_o_pfx(capsys):
    _montar_launch_kwargs("perfil", cert_pfx_path=PFX_SENTINELA,
                          cert_pfx_passphrase=SENHA_SENTINELA)
    saida = capsys.readouterr()
    for sentinela in (PFX_SENTINELA, SENHA_SENTINELA, "SEGREDO_TESTE"):
        assert sentinela not in saida.out
        assert sentinela not in saida.err


def test_montar_launch_kwargs_nao_imprime_o_cn(capsys, monkeypatch):
    monkeypatch.setenv("CERT_SUBJECT_CN", CN_SENTINELA)
    _montar_launch_kwargs("perfil")
    saida = capsys.readouterr()
    assert CN_SENTINELA not in saida.out
    assert CN_SENTINELA not in saida.err


def test_build_auto_select_flag_nao_imprime_o_cn(capsys):
    """O CN VAI para a flag do Chrome — uso funcional, permitido. O que nao
    pode e ele aparecer na saida."""
    flag = _build_auto_select_cert_flag(CN_SENTINELA)
    saida = capsys.readouterr()
    assert CN_SENTINELA in flag          # uso funcional preservado
    assert CN_SENTINELA not in saida.out
    assert CN_SENTINELA not in saida.err


@pytest.mark.parametrize("sentinela", [CNPJ_SENTINELA, URL_SENTINELA, "state=SEGREDO_TESTE_123"])
def test_sentinelas_nao_aparecem_no_codigo_fonte(sentinela):
    """Guarda contra sentinela colada por engano no modulo de producao."""
    assert sentinela not in FONTE.read_text(encoding="utf-8")


# ══ Nada que veio do navegador entra cru no log ══════════════════════════════
#
# REGRESSAO REAL (run de 18/08/2026): `[diag] inputs do formPJ: [...]` saiu com
# o `value` de cada input do popup de perfil — e um deles e o CNPJ recem
# preenchido. A camada estatica acima nao alcancava o caso: o valor nao vinha de
# uma variavel proibida, vinha de `page.evaluate`.
#
# A defesa que se testa aqui e a de Python — `_diag_inputs` filtra chaves —,
# porque ela e pura e roda sem navegador. O JS ja devolve a forma reduzida, mas
# quem GARANTE e o filtro.

CAMPOS_QUE_NUNCA_SAEM = ("value", "textContent", "innerHTML", "outerHTML",
                         "placeholder", "defaultValue")


def test_diag_inputs_descarta_o_conteudo_do_campo():
    bruto = [{"idx": 0, "type": "text", "name": "ni", "id": "ni",
              "value": CNPJ_SENTINELA, "visible": True, "preenchido": True}]
    saida = login._diag_inputs(bruto)
    assert CNPJ_SENTINELA not in repr(saida)
    assert saida == [{"idx": 0, "type": "text", "name": "ni", "id": "ni",
                      "visible": True, "preenchido": True}]


@pytest.mark.parametrize("campo", CAMPOS_QUE_NUNCA_SAEM)
def test_diag_inputs_descarta_qualquer_campo_de_conteudo(campo):
    """Lista fechada de chaves permitidas: uma chave nova do navegador nao
    entra por acidente."""
    saida = login._diag_inputs([{"idx": 0, campo: CNPJ_SENTINELA}])
    assert CNPJ_SENTINELA not in repr(saida)


def test_diag_inputs_preserva_o_que_o_diagnostico_precisa():
    """Sanitizar nao pode esvaziar o diagnostico: o que se procurava ali era o
    botao 'Alterar' e se o campo estava preenchido."""
    saida = login._diag_inputs([{"idx": 3, "type": "submit", "name": "b", "id": "b",
                                 "visible": True, "preenchido": True,
                                 "parece_alterar": True, "aciona_captcha": True,
                                 "value": "Alterar"}])
    assert saida[0]["parece_alterar"] is True
    assert saida[0]["aciona_captcha"] is True
    assert saida[0]["visible"] is True
    assert "value" not in saida[0]


@pytest.mark.parametrize("entrada", [None, "texto", 42, [None, 7, "x"]])
def test_diag_inputs_tolera_retorno_estranho_do_navegador(entrada):
    """Se o evaluate devolver outra coisa, nada vaza e nada explode."""
    assert login._diag_inputs(entrada) == []


def test_resultado_de_clique_e_vocabulario_fechado():
    for esperado in login.RESULTADOS_CLIQUE:
        assert login._resultado_de_clique(esperado) == esperado
    assert login._resultado_de_clique(CNPJ_SENTINELA) == "desconhecido"
    assert login._resultado_de_clique(None) == "desconhecido"


def test_nenhum_js_do_modulo_devolve_o_conteudo_de_um_campo():
    """Defesa em profundidade: o JS tambem nao pode montar `value` no retorno.

    Nao substitui o filtro de chaves — reforca. Um `value:` num literal de
    objeto JS foi exatamente a forma do vazamento.
    """
    texto = FONTE.read_text(encoding="utf-8")
    for marca in ("value: i.value", "value: el.value", "value: input.value"):
        assert marca not in texto


def test_nenhuma_saida_interpola_objeto_de_excecao():
    """`str(exc)` de erro do Playwright carrega seletor, URL e trecho de DOM.

    Sai o nome da classe; nunca a mensagem. Este teste reprova `{e}`, `{exc}`,
    `{e2}`, `{e3}` — e aceita `{type(e).__name__}`.
    """
    arvore = ast.parse(FONTE.read_text(encoding="utf-8"))
    achados = []
    for chamada in _chamadas_de_saida(arvore):
        for arg in ast.walk(chamada):
            if not isinstance(arg, ast.FormattedValue):
                continue
            trecho = ast.unparse(arg.value)
            if isinstance(arg.value, ast.Name) and re.fullmatch(r"e\d*|exc\d*", trecho):
                achados.append(f"linha {chamada.lineno}: {{{trecho}}}")
    assert not achados, "log com mensagem de excecao:\n  " + "\n  ".join(achados)

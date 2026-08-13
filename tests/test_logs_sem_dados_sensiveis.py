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
from pathlib import Path

import pytest

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
    import re
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

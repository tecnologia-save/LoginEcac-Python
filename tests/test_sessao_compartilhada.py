"""Quem lanca o navegador fecha o navegador — e quem recebe uma sessao, nao.

Execucao real no AutoHub (SHA 44cba8e): o Servicos RF autenticou, representou o
CNPJ e concluiu pagamentos. Logo depois:

    Lancando Chrome... / Chrome lancado. / Pagina obtida. / Abrindo o eCAC...
    Clicando em 'Entrar com gov.br'...
    botao 'Seu certificado digital' nao encontrado.
    Login no eCAC nao concluido.

Um SEGUNDO Chrome foi lancado, com perfil vazio, e o login recomecou do zero.

`main` misturava tres coisas: lancar sessao, autenticar e trocar de perfil.
`garantir_acesso_ecac` e a segunda e a terceira, sobre uma sessao que ja existe.

E os caminhos de falha de `main` decidiam individualmente se fechavam o
navegador — alguns nao fechavam. Um Chrome vivo segura o diretorio de perfil, e
quem tentasse remover o temporario depois batia em PermissionError no Windows.
Agora o fechamento e de quem lancou, num ponto so.

Dados sinteticos. Nenhum CNPJ, certificado ou pagina de cliente.
"""
import ast
import inspect
import pathlib

from ecac_login import login

FONTE = pathlib.Path(login.__file__).read_text(encoding="utf-8")
ARVORE = ast.parse(FONTE)


def _funcao(nome):
    for no in ast.walk(ARVORE):
        if isinstance(no, ast.FunctionDef) and no.name == nome:
            return no
    raise AssertionError(f"funcao {nome} nao existe")


# ══ 1 · A separacao ═════════════════════════════════════════════════════════

def test_garantir_acesso_recebe_uma_pagina_e_nao_lanca_nada():
    """Sem `sync_playwright`, sem `launch_persistent_context`."""
    corpo = ast.dump(_funcao("garantir_acesso_ecac"))
    assert "sync_playwright" not in corpo
    assert "launch_persistent_context" not in corpo
    assert "new_context" not in corpo

    parametros = list(inspect.signature(login.garantir_acesso_ecac).parameters)
    assert parametros[0] == "page"
    assert parametros[1] == "cnpj"


def test_garantir_acesso_nunca_fecha_a_sessao():
    """A sessao pertence a quem a criou. Fechar aqui derrubaria as etapas
    seguintes da execucao."""
    corpo = _funcao("garantir_acesso_ecac")
    chamadas = {n.func.attr for n in ast.walk(corpo)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "stop" not in chamadas
    fechamentos = [n for n in ast.walk(corpo)
                   if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr == "close"
                   and getattr(n.func.value, "id", None) in ("context", "p")]
    assert fechamentos == []


def _returns_proprios(funcao):
    """`Return`s da funcao, sem descer nas aninhadas (`_ja_logado` e cia.)."""
    aninhadas = {id(n) for f in ast.walk(funcao)
                 if isinstance(f, ast.FunctionDef) and f is not funcao
                 for n in ast.walk(f)}
    return [n for n in ast.walk(funcao)
            if isinstance(n, ast.Return) and n.value is not None
            and id(n) not in aninhadas]


def test_garantir_acesso_devolve_booleano():
    """Nao devolve sessao: ela nao e dele."""
    retornos = _returns_proprios(_funcao("garantir_acesso_ecac"))
    assert retornos
    for no in retornos:
        assert isinstance(no.value, ast.Constant), ast.dump(no.value)
        assert isinstance(no.value.value, bool)


def test_main_continua_devolvendo_a_sessao():
    """Retrocompatibilidade: consumidores standalone nao mudam."""
    fonte = inspect.getsource(login.main)
    assert "return p, context, page" in fonte
    assert "sync_playwright().start()" in fonte


def test_main_delega_o_fluxo_para_garantir_acesso():
    assert "garantir_acesso_ecac(" in inspect.getsource(login.main)


# ══ 2 · Quem lanca, fecha — num ponto so ════════════════════════════════════

def test_main_fecha_a_sessao_em_qualquer_falha():
    """Antes, cada caminho de falha decidia por si — e alguns vazavam o Chrome.

    A conta era EXATA (`== 2`) e envelheceu mal: quando o `except AcessoBloqueado`
    passou a fechar a sessao tambem — um terceiro caminho de falha fazendo
    exatamente o que este teste quer —, o teste acusou regressao onde houve
    conserto. O que importa nao e QUANTOS caminhos existem, e sim que nenhum
    deles saia sem fechar.
    """
    fonte = inspect.getsource(login.main)
    saidas_de_falha = fonte.count("return None")
    fechamentos = fonte.count("encerrar_sessao(p, context)")
    assert fechamentos >= saidas_de_falha, (
        f"{saidas_de_falha} saída(s) de falha para {fechamentos} fechamento(s): "
        "algum caminho vaza o Chrome")
    assert "except BaseException:" in fonte


def test_encerrar_sessao_e_idempotente():
    """Chamar duas vezes nao pode virar erro."""
    class _Ctx:
        def __init__(self):
            self.fechados = 0

        def close(self):
            self.fechados += 1
            if self.fechados > 1:
                raise RuntimeError("ja fechado")

    class _P:
        def __init__(self):
            self.parados = 0

        def stop(self):
            self.parados += 1
            if self.parados > 1:
                raise RuntimeError("ja parado")

    ctx, pw = _Ctx(), _P()
    login.encerrar_sessao(pw, ctx)
    login.encerrar_sessao(pw, ctx)          # nao levanta
    assert (ctx.fechados, pw.parados) == (2, 2)


def test_encerrar_sessao_tolera_none():
    login.encerrar_sessao(None, None)
    login.encerrar_sessao()


def test_nenhum_input_bloqueante_no_fluxo():
    """Stdin do agente e nulo: esperar por ENTER travaria a run em vez de falhar."""
    chamadas = [n for n in ast.walk(ARVORE)
                if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "input"]
    assert chamadas == []


def test_a_api_publica_expoe_as_duas_formas():
    import ecac_login

    assert "fazer_login" in ecac_login.__all__          # cria sessao
    assert "garantir_acesso_ecac" in ecac_login.__all__  # usa sessao
    assert "encerrar_sessao" in ecac_login.__all__

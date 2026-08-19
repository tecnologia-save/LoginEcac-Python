"""Fallback COMPORTAMENTAL: sessao fornecida que nao autentica.

Os testes de `test_sessao_compartilhada.py` sao estruturais — leem a AST e
provam que `sync_playwright` e `launch_persistent_context` nao aparecem em
`garantir_acesso_ecac`. Isso e um gate, nao uma prova de execucao: um caminho
que chamasse a fabrica por outro nome, ou um helper importado, passaria.

Aqui a funcao roda de verdade sobre uma Page dublada que NAO autentica — o
caminho exato da run de 09:58, em que o botao do certificado nao apareceu — e
o lancador de navegador e uma bomba: se for tocado, o teste falha.

O contrato provado: recebida uma Page, o desfecho negativo e `False`. Nunca
"entao lanco um Chrome meu".

Dados sinteticos. Nenhum CNPJ, certificado ou pagina de cliente.
"""
import pytest

from ecac_login import login

CNPJ = "00011122000133"


class _Locator:
    """Nada visivel: nem o link de voltar, nem o botao do gov.br."""

    @property
    def first(self):
        return self

    def is_visible(self, **_kw):
        return False

    def wait_for(self, **_kw):
        raise RuntimeError("nao visivel")

    def click(self, **_kw):
        raise AssertionError("nao deveria clicar no que nao esta visivel")


class _PageNaoAutenticada:
    """Uma sessao viva, porem deslogada. Registra o que sofreu."""

    def __init__(self):
        self.urls = []
        self.fechada = False

    @property
    def url(self):
        # Fora do eCAC: `_ja_logado()` e falso, e o fluxo vai para o login.
        return "https://sso.acesso.gov.br/login"

    def goto(self, url, **_kw):
        self.urls.append(url)

    def wait_for_timeout(self, _ms):
        pass

    def content(self):
        return "<html></html>"

    def locator(self, _seletor):
        return _Locator()

    def close(self):
        self.fechada = True


@pytest.fixture
def sem_navegador(monkeypatch):
    """Qualquer tentativa de lancar navegador estoura o teste."""
    def bomba(*_a, **_k):
        raise AssertionError("garantir_acesso_ecac lancou navegador proprio")

    monkeypatch.setattr(login, "sync_playwright", bomba)


def test_sessao_fornecida_que_nao_autentica_devolve_false(sem_navegador):
    page = _PageNaoAutenticada()
    assert login.garantir_acesso_ecac(page, CNPJ) is False


def test_a_pagina_recebida_e_a_que_navega(sem_navegador):
    """A transicao e um `goto` na Page do caller — nao uma aba nova."""
    page = _PageNaoAutenticada()
    login.garantir_acesso_ecac(page, CNPJ)
    assert page.urls == [login.ECAC_URL]


def test_o_fallback_nao_fecha_a_sessao_de_quem_a_criou(sem_navegador):
    """Falhar aqui nao autoriza derrubar o navegador da execucao: as etapas
    seguintes, e o proprio teardown, ainda precisam dele."""
    page = _PageNaoAutenticada()
    login.garantir_acesso_ecac(page, CNPJ)
    assert page.fechada is False

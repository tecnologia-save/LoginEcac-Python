"""A guarda não pode derrubar o login por não ter conseguido ler a página.

`page.content()` levanta enquanto a navegação está em curso, e os três usos
dela são guardas para condições raras. Deixar a exceção subir invertia a
relação: a guarda ficava mais frágil que o problema que protege.
"""

import pytest

from ecac_login.login import _conteudo


class PaginaFalsa:
    """Página que só devolve o HTML depois de N leituras."""

    def __init__(self, falhas: int, html: str = "<html>ok</html>"):
        self.falhas = falhas
        self.html = html
        self.leituras = 0
        self.esperas = 0

    def content(self):
        self.leituras += 1
        if self.leituras <= self.falhas:
            raise Exception(
                "Page.content: Unable to retrieve content because the page is navigating"
            )
        return self.html

    def wait_for_load_state(self, *_a, **_k):
        self.esperas += 1

    def wait_for_timeout(self, *_a, **_k):
        self.esperas += 1


def test_devolve_o_html_quando_a_pagina_esta_parada():
    pagina = PaginaFalsa(falhas=0)
    assert _conteudo(pagina) == "<html>ok</html>"
    assert pagina.leituras == 1
    assert pagina.esperas == 0, "página parada não deve custar espera nenhuma"


def test_insiste_quando_a_pagina_esta_navegando():
    pagina = PaginaFalsa(falhas=2)
    assert _conteudo(pagina) == "<html>ok</html>"
    assert pagina.leituras == 3


def test_devolve_vazio_em_vez_de_levantar():
    """O ponto do conserto: a guarda passa, a run continua.

    Não ter lido não é o mesmo que a mensagem não estar lá. Um falso negativo
    aqui adia a detecção; a exceção encerrava a run na hora.
    """
    pagina = PaginaFalsa(falhas=99)
    assert _conteudo(pagina) == ""


def test_a_guarda_nao_propaga_a_excecao():
    pagina = PaginaFalsa(falhas=99)
    try:
        _conteudo(pagina)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"guarda propagou {type(e).__name__}: {e}")

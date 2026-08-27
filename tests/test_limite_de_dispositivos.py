"""A tela do limite de dispositivos não é "botão não encontrado".

Execução real de 27/08/2026, dois arquivos de log da mesma máquina:

    15:15:51  Login: numero maximo de dispositivos conectados atingido.
    15:17:03  Login: botao 'Seu certificado digital' nao encontrado.
    15:17:45  Login: botao 'Seu certificado digital' nao encontrado.
    15:18:58  Login: botao 'Seu certificado digital' nao encontrado.

e, no log da automação chamadora, seis vezes a mesma linha muda:

    15:17:04  [CNPJ 09490424000156] login nao concluido.

O limite foi detectado UMA vez — logo depois de apresentar o certificado, que
é o único lugar onde a verificação existia. Nas tentativas seguintes o gov.br
já servia a tela do limite no lugar da tela de login, e aí não há botão de
certificado nenhum para achar: a verificação nunca era alcançada, e a causa
degradava em "botão não encontrado".

Isso importa porque os dois desfechos pedem coisas opostas. "Botão não
encontrado" é defeito de página, e insistir é razoável. O limite de
dispositivos não passa com o tempo — só cai quando alguém desconecta uma
sessão em gov.br — e insistir é garantir o mesmo fim mais tarde.

Dados sintéticos. Nenhum CNPJ, certificado ou página de cliente.
"""
import pytest

from ecac_login import login
from ecac_login.login import DispositivosMaximo, MENSAGEM_DISPOSITIVOS_MAXIMOS

CNPJ = "00011122000133"


class _Locator:
    """Nada visível — nem o botão do gov.br, nem o do certificado."""

    @property
    def first(self):
        return self

    def is_visible(self, **_kw):
        return False

    def wait_for(self, **_kw):
        raise RuntimeError("nao visivel")

    def click(self, **_kw):
        raise AssertionError("nao deveria clicar no que nao esta visivel")


class _PaginaSemBotao:
    """Sessão viva e deslogada, sem botão de certificado. `html` decide o porquê."""

    def __init__(self, html: str):
        self.html = html
        self.fechada = False

    @property
    def url(self):
        return "https://sso.acesso.gov.br/login"

    def goto(self, _url, **_kw):
        pass

    def wait_for_timeout(self, _ms):
        pass

    def content(self):
        return self.html

    def locator(self, _seletor):
        return _Locator()

    def close(self):
        self.fechada = True


@pytest.fixture
def ate_o_certificado(monkeypatch):
    """Encurta o caminho até a etapa do certificado, que é a testada aqui.

    Tudo o que vem antes — achar o 'Entrar com gov.br', provar que o clique
    reagiu, resolver o captcha — tem teste próprio e exige uma página dublada
    inteira. Aqui esses passos são dados por bons para que o assunto do arquivo
    seja o único a decidir o desfecho.
    """
    def bomba(*_a, **_k):
        raise AssertionError("garantir_acesso_ecac lancou navegador proprio")

    monkeypatch.setattr(login, "sync_playwright", bomba)
    monkeypatch.setattr(login, "_achar_govbr", lambda *a, **k: (_Locator(), "#govbr"))
    monkeypatch.setattr(login, "_pagina_pronta", lambda *a, **k: None)
    monkeypatch.setattr(login, "_pronto_para_govbr", lambda *a, **k: None)
    monkeypatch.setattr(login, "_prova_govbr", lambda *a, **k: (lambda: True))
    monkeypatch.setattr(login, "_clicar_ate_reagir", lambda *a, **k: True)
    monkeypatch.setattr(login, "_try_solve_captcha", lambda *a, **k: True)


PAGINA_DO_LIMITE = (
    f"<html><body><h1>Acesso negado</h1>"
    f"<p>{MENSAGEM_DISPOSITIVOS_MAXIMOS}</p></body></html>"
)


def test_tela_do_limite_sem_botao_levanta_dispositivos_maximo(ate_o_certificado):
    """O caso do log: a tela do limite substituiu a do certificado.

    Antes, isto devolvia `False` — que a automação chamadora traduz como
    "login não concluído", sem nada que aponte para a ação que resolve.
    """
    page = _PaginaSemBotao(PAGINA_DO_LIMITE)
    with pytest.raises(DispositivosMaximo):
        login.garantir_acesso_ecac(page, CNPJ)


def test_botao_ausente_sem_a_mensagem_continua_devolvendo_false(ate_o_certificado):
    """A regressão que importa: só a mensagem muda o desfecho.

    Página quebrada de verdade continua sendo `False`, e não uma exceção que
    faria o chamador anunciar um limite que não existe.
    """
    page = _PaginaSemBotao("<html><body>pagina qualquer</body></html>")
    assert login.garantir_acesso_ecac(page, CNPJ) is False


def test_o_limite_nao_fecha_a_sessao_de_quem_a_criou(ate_o_certificado):
    """Quem lançou o navegador é quem o fecha — inclusive neste desfecho."""
    page = _PaginaSemBotao(PAGINA_DO_LIMITE)
    with pytest.raises(DispositivosMaximo):
        login.garantir_acesso_ecac(page, CNPJ)
    assert page.fechada is False

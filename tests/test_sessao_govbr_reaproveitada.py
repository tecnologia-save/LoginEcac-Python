"""O gov.br reaproveitou a sessão: depois do captcha, foi direto para o eCAC.

Execução real de 09/10/2026 (AUT-0015, na máquina edge):

    15:58:39  Procurando botao 'Seu certificado digital'...
    15:59:01  -> botao 'Seu certificado digital' nao encontrado.
    15:59:05  -> botao nao encontrado mas pagina ja esta logada. Continuando.

Vinte e dois segundos esperando um botão que nunca viria: a página já estava
no eCAC. A espera era SÓ pelo botão (20s no primeiro seletor + 2s em cada um
dos outros), e o login só era notado depois de ela estourar. Agora a espera é
pelo botão OU pelo login — o que vier primeiro —, com o mesmo teto.

Dados sintéticos. Nenhum CNPJ, certificado ou página de cliente.
"""
import time

import pytest

from ecac_login import login

CNPJ = "00011122000133"
URL_GOVBR = "https://sso.acesso.gov.br/login"
URL_ECAC = "https://cav.receita.fazenda.gov.br/ecac/"


class _ChegouNoPerfil(Exception):
    """O login passou da etapa testada aqui — o resto tem teste próprio."""


class _Botao:
    def __init__(self, pagina, seletor):
        self._pagina, self._seletor = pagina, seletor

    @property
    def first(self):
        return self

    def is_visible(self, **_kw):
        return self._pagina.visivel(self._seletor)

    def wait_for(self, **_kw):
        if not self.is_visible():
            raise RuntimeError("nao visivel")

    def click(self, **_kw):
        self._pagina.clicar(self._seletor)


class _Pagina:
    """O botão do certificado e o login, cada um aparecendo depois de N consultas
    ao botão — é assim que o tempo passa nesta página."""

    def __init__(self, loga_apos=None, botao_apos=None):
        self.loga_apos, self.botao_apos = loga_apos, botao_apos
        self.consultas_ao_botao = 0
        self.cliques = []
        self.logado = False

    @property
    def url(self):
        return URL_ECAC if self.logado else URL_GOVBR

    def visivel(self, seletor):
        if seletor == "#login-certificate":
            self.consultas_ao_botao += 1
            if self.loga_apos is not None and self.consultas_ao_botao >= self.loga_apos:
                self.logado = True
            return (self.botao_apos is not None and not self.logado
                    and self.consultas_ao_botao >= self.botao_apos)
        if seletor == "#btnPerfil":
            return self.logado
        return False

    def clicar(self, seletor):
        self.cliques.append(seletor)
        self.logado = True          # o certificado apresentado conclui o login

    def locator(self, seletor):
        return _Botao(self, seletor)

    def goto(self, _url, **_kw):
        pass

    def wait_for_timeout(self, _ms):
        pass

    def wait_for_load_state(self, *_a, **_kw):
        pass

    def is_closed(self):
        return False

    def content(self):
        return "<html><body></body></html>"


@pytest.fixture
def ate_o_certificado(monkeypatch):
    """Os passos antes do certificado dados por bons (têm teste próprio), e o
    perfil de acesso — o passo seguinte ao login — como ponto de chegada."""
    def bomba(*_a, **_k):
        raise AssertionError("garantir_acesso_ecac lancou navegador proprio")

    def chegou(*_a, **_k):
        raise _ChegouNoPerfil()

    monkeypatch.setattr(login, "sync_playwright", bomba)
    monkeypatch.setattr(login, "_achar_govbr", lambda *a, **k: (object(), "#govbr"))
    monkeypatch.setattr(login, "_pagina_pronta", lambda *a, **k: None)
    monkeypatch.setattr(login, "_pronto_para_govbr", lambda *a, **k: None)
    monkeypatch.setattr(login, "_prova_govbr", lambda *a, **k: (lambda: True))
    monkeypatch.setattr(login, "_clicar_ate_reagir", lambda *a, **k: True)
    monkeypatch.setattr(login, "_try_solve_captcha", lambda *a, **k: True)
    monkeypatch.setattr(login, "_abrir_popup_de_perfil", chegou)


def test_sessao_reaproveitada_e_notada_sem_esperar_o_teto(ate_o_certificado, capsys):
    """O caso do log: o login chega durante a espera pelo botão."""
    page = _Pagina(loga_apos=3)
    inicio = time.monotonic()
    with pytest.raises(_ChegouNoPerfil):
        login.garantir_acesso_ecac(page, CNPJ)
    assert time.monotonic() - inicio < 5            # e não os ~22s de antes
    assert page.cliques == []
    saida = capsys.readouterr().out
    assert "sessao do gov.br reaproveitada" in saida
    assert "botao 'Seu certificado digital' nao encontrado" not in saida


def test_botao_que_demora_a_aparecer_ainda_e_clicado_uma_vez(ate_o_certificado):
    """A regressão que importa: o caminho normal continua clicando o botão."""
    page = _Pagina(botao_apos=4)
    with pytest.raises(_ChegouNoPerfil):
        login.garantir_acesso_ecac(page, CNPJ)
    assert page.cliques == ["#login-certificate"]


def test_sem_botao_e_sem_login_continua_devolvendo_false(ate_o_certificado, monkeypatch):
    """Página quebrada de verdade: o mesmo `False` de antes, só que no teto curto."""
    monkeypatch.setattr(login, "ESPERA_BOTAO_CERTIFICADO_MS", 0)
    assert login.garantir_acesso_ecac(_Pagina(), CNPJ) is False

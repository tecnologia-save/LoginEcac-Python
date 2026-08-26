"""Clique em falso: o Playwright diz "clicado" e ninguem atendeu.

`locator.click()` voltar sem excecao prova UMA coisa: o evento foi despachado.
O elemento estava visivel, estavel, recebendo cliques, e o mouse desceu e subiu
em cima dele. Se o script que responde pelo botao ainda nao rodou, o clique cai
no vazio — e o log dizia "-> clicado." do mesmo jeito.

No 'Entrar com gov.br' isso saia caro: sem reacao, o passo seguinte procurava
'Seu certificado digital' numa pagina que nunca mudou, e a empresa terminava
como "falha no login" sem ninguem saber por que.

Os dois contratos provados aqui:

  1. quem decide se o clique pegou e a PROVA, nao o retorno do click;
  2. a PRIMEIRA tentativa clica, sem consultar a prova antes.

O item 2 nasceu de um defeito real, e por isso e o mais importante deste
arquivo. Consultar a prova antes do primeiro clique parece prudente e nao e:
prova mede o estado da tela, e um estado que ja existia no carregamento passa
por reacao. Na pagina do e-CAC ha um iframe do hCaptcha embutido desde o
primeiro byte; a prova dava positivo, e o botao deixava de ser clicado por
inteiro. Evidencia so vale como MUDANCA — e antes do primeiro clique nao ha com
o que comparar.

Sem navegador: o que se testa e a politica.
"""
from ecac_login import login


class _Botao:
    """Botao que so atende depois de `atende_a_partir_de` cliques.

    Modela o defeito real: o elemento existe e aceita o clique desde o inicio;
    o que falta e o handler do outro lado.
    """

    def __init__(self, atende_a_partir_de=1, reage_depois_de=0):
        self.cliques = 0
        self.atendidos = 0
        self._atende = atende_a_partir_de
        self._reage_depois = reage_depois_de
        self.reagiu = False

    # -- superficie que `_clicar_por_todas_as_vias` usa --
    def scroll_into_view_if_needed(self, **_kw):
        pass

    def click(self, **_kw):
        self._registrar()

    def dispatch_event(self, *_a, **_kw):
        self._registrar()

    def _registrar(self):
        self.cliques += 1
        if self.cliques >= self._atende:
            self.atendidos += 1
            if self._reage_depois == 0:
                self.reagiu = True

    def sondar(self):
        """Chamada a cada olhada na tela; imita reacao que demora a aparecer."""
        if self.atendidos and self._reage_depois > 0:
            self._reage_depois -= 1
            if self._reage_depois == 0:
                self.reagiu = True
        return self.reagiu


class _PaginaMuda:
    """Page dublada. Sem seletor CSS, a via do <script> nem e montada."""

    def add_script_tag(self, **_kw):
        raise AssertionError("nao deveria injetar script sem seletor css")


def _tentar(botao, **kw):
    kw.setdefault("espera_ms", 600)
    return login._clicar_ate_reagir(_PaginaMuda(), lambda: botao, "",
                                    botao.sondar, "o botao", **kw)


def test_botao_que_responde_leva_um_clique_so():
    botao = _Botao()
    assert _tentar(botao) is True
    assert botao.cliques == 1


def test_reacao_lenta_nao_vira_clique_repetido():
    # O botao atende na hora; a tela so muda algumas olhadas depois. Concluir
    # "nao reagiu" aqui e clicar de novo e o pior desfecho possivel: dois
    # envios seguidos sao o que o gov.br le como acesso automatizado.
    botao = _Botao(reage_depois_de=2)
    assert _tentar(botao) is True
    assert botao.cliques == 1


def test_clique_em_falso_e_percebido_e_repetido():
    # So o terceiro clique encontra o handler armado.
    botao = _Botao(atende_a_partir_de=3)
    assert _tentar(botao) is True
    assert botao.cliques == 3
    assert botao.atendidos == 1


def test_botao_morto_devolve_falso_em_vez_de_sucesso_fingido():
    botao = _Botao(atende_a_partir_de=99)
    assert _tentar(botao) is False
    assert botao.cliques == login.CLIQUES_GOVBR
    assert botao.atendidos == 0


def test_o_primeiro_clique_acontece_mesmo_com_a_prova_ja_satisfeita():
    # A regressao, em uma linha. A pagina do e-CAC carrega com um iframe do
    # hCaptcha embutido; qualquer prova que o aceite responde "ja reagiu" antes
    # de alguem clicar. Pular o clique por causa disso quebrou o login inteiro
    # — nenhuma empresa passava da tela de entrada.
    botao = _Botao()
    botao.reagiu = True
    assert _tentar(botao) is True
    assert botao.cliques == 1


def test_da_segunda_tentativa_em_diante_a_prova_evita_o_clique_repetido():
    # O outro lado da moeda: se a reacao chegou entre uma tentativa e outra,
    # nao se clica de novo.
    class _ReageSozinho(_Botao):
        def __init__(self):
            super().__init__(atende_a_partir_de=99)
            self._olhadas = 0

        def sondar(self):
            # A janela de 100 ms cabe duas olhadas; a terceira ja e a do topo
            # da 2a tentativa, e e nela que a reacao aparece.
            self._olhadas += 1
            return self._olhadas > 2

    botao = _ReageSozinho()
    assert _tentar(botao, espera_ms=100) is True
    assert botao.cliques == 1


def test_prova_manda_mais_que_a_excecao_do_clique():
    # Nenhuma via funciona. Isso pode ser a reacao chegando atrasada — tratar
    # como falha jogaria fora uma entrada bem-sucedida.
    class _Some:
        def scroll_into_view_if_needed(self, **_kw):
            pass

        def click(self, **_kw):
            raise RuntimeError("element is not attached to the DOM")

        def dispatch_event(self, *_a, **_kw):
            raise RuntimeError("element is not attached to the DOM")

    def _chamar(prova):
        return login._clicar_ate_reagir(_PaginaMuda(), lambda: _Some(), "",
                                        prova, "o botao", espera_ms=300)

    assert _chamar(lambda: True) is True
    assert _chamar(lambda: False) is False


def test_a_janela_de_prova_e_folgada():
    # Regressao de calibragem: uma janela curta transformaria reacao lenta em
    # clique repetido, que e o caminho para o bloqueio por acesso automatizado.
    assert login.ESPERA_PROVA_MS >= 5_000


def test_o_clique_forcado_e_a_ultima_via_e_nao_a_primeira():
    # `force=True` pula as checagens do Playwright e clica NAS COORDENADAS: com
    # um overlay por cima, acerta o overlay, nao levanta erro e nao faz nada.
    # Uma via de reserva que mente e pior do que nenhuma, entao ela vai por
    # ultimo — medido numa replica com overlay transparente.
    vistas = []

    class _Registra:
        def scroll_into_view_if_needed(self, **_kw):
            pass

        def click(self, **kw):
            vistas.append("forcado" if kw.get("force") else "real")
            raise RuntimeError("nao pegou")

        def dispatch_event(self, *_a, **_kw):
            vistas.append("evento")
            raise RuntimeError("nao pegou")

    login._clicar_por_todas_as_vias(_PaginaMuda(), lambda: _Registra(), "",
                                    "o botao")
    assert vistas[0] == "real"
    assert vistas[-1] == "forcado"

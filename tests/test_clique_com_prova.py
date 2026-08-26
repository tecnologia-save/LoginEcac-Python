"""Clique em falso: o Playwright diz "clicado" e ninguem atendeu.

`locator.click()` voltar sem excecao prova UMA coisa: o evento foi despachado.
O elemento estava visivel, estavel, recebendo cliques, e o mouse desceu e subiu
em cima dele. Se o script que responde pelo botao ainda nao rodou, o clique cai
no vazio — e o log dizia "-> clicado." do mesmo jeito.

No 'Entrar com gov.br' isso saia caro: sem reacao, o passo seguinte procurava
'Seu certificado digital' numa pagina que nunca mudou, e a empresa terminava
como "falha no login" sem ninguem saber por que.

O contrato provado aqui: quem decide se o clique pegou e a PROVA, nao o retorno
do click. E o outro lado, que importa tanto quanto — um clique que reage devagar
NAO pode virar dois cliques. Dois envios seguidos sao justamente o que o gov.br
le como acesso automatizado.

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

    def click(self, **_kw):
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


def _tentar(botao, **kw):
    kw.setdefault("espera_ms", 600)
    return login._clicar_ate_reagir(lambda: botao, botao.sondar, "o botao", **kw)


def test_botao_que_responde_leva_um_clique_so():
    botao = _Botao()
    assert _tentar(botao) is True
    assert botao.cliques == 1


def test_reacao_lenta_nao_vira_clique_repetido():
    # O botao atende na hora; a tela so muda algumas olhadas depois. Concluir
    # "nao reagiu" aqui e clicar de novo e o pior desfecho possivel.
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


def test_nao_clica_quando_a_prova_ja_esta_satisfeita():
    # Se a tela ja esta onde se queria chegar, nao ha clique a dar.
    botao = _Botao()
    botao.reagiu = True
    assert _tentar(botao) is True
    assert botao.cliques == 0


def test_prova_manda_mais_que_a_excecao_do_clique():
    # O elemento sumir na hora de clicar pode ser a reacao chegando atrasada.
    # Tratar como falha jogaria fora uma entrada bem-sucedida.
    class _Some:
        def click(self, **_kw):
            raise RuntimeError("element is not attached to the DOM")

    assert login._clicar_ate_reagir(lambda: _Some(), lambda: True,
                                    "o botao", espera_ms=300) is True
    assert login._clicar_ate_reagir(lambda: _Some(), lambda: False,
                                    "o botao", espera_ms=300) is False


def test_a_janela_de_prova_e_folgada():
    # Regressao de calibragem: uma janela curta transformaria reacao lenta em
    # clique repetido, que e o caminho para o bloqueio por acesso automatizado.
    assert login.ESPERA_PROVA_MS >= 5_000

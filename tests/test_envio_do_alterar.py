"""Quem envia o formulário de perfil: a página ou o nosso clique.

O eCAC recusa a troca de perfil com "A execução possui atributos que caracteriza
acesso automatizado". Na execução de 27/08/2026, as 29 trocas se dividiram assim:

    clique confirmou      ->  0 trocas | 11 "acesso automatizado" | 6 recusas
    clique NAO confirmou  -> 12 trocas |  0 "acesso automatizado" | 0 recusas

Nenhuma troca bem-sucedida veio de um clique que confirmou, e o `[diag]` do
mesmo log mostra o mecanismo: nas passagens que deram certo o botão aparecia com
`visible: False` e o campo com `preenchido: False` — o formulário JÁ estava sendo
enviado por um ajax da própria página, e o clique chegava tarde ou nem chegava.

Daí a política que se prova aqui: esperar a página enviar sozinha, e clicar só se
ela não enviar. E dizer QUEM enviou, porque é esse par (quem enviou, o que o
portal respondeu) que confirma ou derruba a leitura na próxima execução real.

Sem navegador: o que está em jogo é a política, não a tela.
"""
import time

from ecac_login import login


class _Tela:
    """Tela que reage sozinha depois de `reage_apos` olhadas (0 = nunca)."""

    def __init__(self, reage_apos=0, reacao="ok"):
        self.olhadas = 0
        self.cliques = 0
        self.dormidas = []
        self._reage_apos = reage_apos
        self._reacao = reacao

    def reacao(self):
        self.olhadas += 1
        if self._reage_apos and self.olhadas >= self._reage_apos:
            return self._reacao
        return ""

    def clicar(self):
        self.cliques += 1

    def dormir(self, ms):
        # Dorme DE VERDADE: a janela e medida em tempo de relogio, e um dorme-
        # nada faria o laco girar solto e mediria outra coisa que nao a politica.
        self.dormidas.append(ms)
        time.sleep(ms / 1000.0)


def _enviar(tela, **kw):
    kw.setdefault("espera_ms", 400)
    kw.setdefault("passo_ms", 10)
    return login._enviar_uma_vez(tela.reacao, tela.clicar, tela.dormir, **kw)


def test_pagina_que_se_envia_sozinha_nao_leva_clique():
    # O caso das 12 trocas que deram certo em producao.
    tela = _Tela(reage_apos=1)
    assert _enviar(tela) == "pagina"
    assert tela.cliques == 0


def test_reacao_que_demora_um_pouco_ainda_evita_o_clique():
    # A reacao nao vem no primeiro olhar: vem algumas centenas de ms depois do
    # `fill`, que e exatamente quando o `[diag]` ja a flagrava em curso.
    tela = _Tela(reage_apos=4)
    assert _enviar(tela) == "pagina"
    assert tela.cliques == 0
    assert tela.olhadas == 4


def test_pagina_que_nao_envia_leva_o_clique():
    # Sem reacao nenhuma, clica-se — o comportamento de antes, so que depois de
    # dar a chance. A janela nunca IMPEDE o envio; no maximo o atrasa.
    tela = _Tela(reage_apos=0)
    assert _enviar(tela) == "clique"
    assert tela.cliques == 1


def test_o_clique_e_um_so():
    # Repeticao de envio e justamente o que o portal le como automacao.
    tela = _Tela(reage_apos=0)
    _enviar(tela)
    assert tela.cliques == 1


def test_mensagem_de_erro_tambem_conta_como_reacao():
    # Uma recusa ja na tela (procuracao vencida) e resposta do portal: clicar
    # em cima dela so mandaria um segundo envio para o mesmo "nao".
    tela = _Tela(reage_apos=1, reacao="erro")
    assert _enviar(tela) == "pagina"
    assert tela.cliques == 0


def test_a_janela_e_respeitada_e_finita():
    # Regressao de calibragem: uma janela que nao termina travaria a empresa.
    tela = _Tela(reage_apos=0)
    inicio = time.monotonic()
    _enviar(tela, espera_ms=200, passo_ms=10)
    gasto = time.monotonic() - inicio
    assert tela.cliques == 1
    assert 0.15 <= gasto < 1.0, gasto
    assert set(tela.dormidas) == {10}


def test_sonda_que_estoura_nao_impede_o_envio():
    # Se a leitura da tela falhar, o desfecho tem de ser o comportamento antigo
    # (clicar), nunca uma empresa parada por causa da sonda.
    class _Quebrada(_Tela):
        def reacao(self):
            raise RuntimeError("execution context was destroyed")

    tela = _Quebrada()
    assert _enviar(tela) == "clique"
    assert tela.cliques == 1


def test_a_janela_padrao_e_curta_o_bastante_para_nao_pesar():
    # Ela e paga uma vez por empresa cujo formulario NAO se envia sozinho.
    # Alguns segundos ali sao ruido perto dos ~20s que uma recusa por
    # "acesso automatizado" custa (espera + recarga + repopular o popup).
    assert login.ESPERA_ENVIO_ESPONTANEO <= 4_000
    assert login.PASSO_ENVIO_ESPONTANEO <= 500

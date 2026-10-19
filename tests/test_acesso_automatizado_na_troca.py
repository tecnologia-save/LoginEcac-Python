""""Acesso automatizado" na troca de perfil: esperar e reenviar NA MESMA janela.

O <p class="mensagemErro"> do eCAC — "Nao foi possivel alterar o perfil de
acesso. A execucao possui atributos que caracteriza acesso automatizado. Tente
novamente mais tarde" — era recusa fatal: o popup fechava, `main` fechava o
navegador e quem chamou abria outro, com login e captcha novos. Relato do
operador (19/10/2026): o certo e esperar 10 s e enviar de novo, ate entrar com o
CNPJ, sem fechar o navegador.

Sem navegador: o que esta em jogo e a POLITICA de `_enviar_ate_o_desfecho`.
"""
import ast
import inspect

from ecac_login import login

AUTOMATIZADO = ("Não foi possível alterar o perfil de acesso. A execução possui atributos "
                "que caracteriza acesso automatizado. Tente novamente mais tarde")
PROCURACAO = "Não existe procuração eletrônica para o detentor"
CNPJ_VAZIO = "CNPJ não preenchido"


class _Portal:
    """Responde a cada envio com o proximo desfecho do roteiro (o ultimo se repete)."""

    def __init__(self, *roteiro):
        self.roteiro = list(roteiro)
        self.envios = 0
        self.preparos = []
        self.esperas = []

    def enviar(self):
        self.envios += 1
        return "pagina"

    def desfecho(self):
        return self.roteiro.pop(0) if len(self.roteiro) > 1 else self.roteiro[0]

    def preparar(self, motivo):
        self.preparos.append(motivo)

    def esperar(self, segundos):
        self.esperas.append(segundos)


def _trocar(portal, insistencias=30, **kw):
    return login._enviar_ate_o_desfecho(portal.enviar, portal.desfecho, portal.preparar,
                                        portal.esperar, insistencias=insistencias, **kw)


def test_acesso_automatizado_ESPERA_10s_e_reenvia_na_mesma_janela_ate_trocar():
    portal = _Portal(("erro", AUTOMATIZADO), ("erro", AUTOMATIZADO), ("ok", ""))
    assert _trocar(portal) == ("ok", "", "pagina")
    assert portal.envios == 3
    assert portal.esperas == [10, 10]
    assert portal.preparos == ["acesso_automatizado"] * 2


def test_a_insistencia_tem_TETO_e_devolve_a_recusa():
    """Um bloqueio que nao passa nao pode virar laco sem fim."""
    portal = _Portal(("erro", AUTOMATIZADO))
    estado, mensagem, _via = _trocar(portal, insistencias=3)
    assert (estado, mensagem) == ("erro", AUTOMATIZADO)
    assert portal.envios == 4 and portal.esperas == [10] * 3


def test_insistencias_ZERO_e_o_comportamento_antigo():
    portal = _Portal(("erro", AUTOMATIZADO))
    assert _trocar(portal, insistencias=0)[0] == "erro"
    assert portal.envios == 1 and portal.esperas == []


def test_procuracao_recusada_encerra_NA_HORA_sem_esperar():
    """Outra tentativa nao muda a resposta da procuracao."""
    portal = _Portal(("erro", PROCURACAO))
    assert _trocar(portal) == ("erro", PROCURACAO, "pagina")
    assert portal.envios == 1 and portal.esperas == [] and portal.preparos == []


def test_cnpj_nao_preenchido_tem_UM_reenvio_como_antes():
    portal = _Portal(("erro", CNPJ_VAZIO))
    assert _trocar(portal)[0:2] == ("erro", CNPJ_VAZIO)
    assert portal.envios == 2 and portal.preparos == ["cnpj_nao_preenchido"]


def test_tela_que_nao_reage_tem_UM_reenvio_com_o_cnpj_repreenchido():
    portal = _Portal(("timeout", ""))
    assert _trocar(portal)[0] == "timeout"
    assert portal.envios == 2 and portal.preparos == ["sem_resposta"]


def test_o_automatizado_nao_gasta_o_reenvio_do_cnpj_vazio():
    portal = _Portal(("erro", AUTOMATIZADO), ("erro", CNPJ_VAZIO), ("erro", AUTOMATIZADO),
                     ("ok", ""))
    assert _trocar(portal)[0] == "ok"
    assert portal.preparos == ["acesso_automatizado", "cnpj_nao_preenchido",
                               "acesso_automatizado"]


def test_o_padrao_e_10s_e_30_insistencias():
    assert login.ESPERA_ACESSO_AUTOMATIZADO_NA_TROCA_S == 10
    assert login.INSISTENCIAS_ACESSO_AUTOMATIZADO_NA_TROCA == 30


def test_o_reconhecimento_e_pelo_texto_e_sem_caixa():
    assert login._eh_acesso_automatizado(AUTOMATIZADO)
    assert login._eh_acesso_automatizado(AUTOMATIZADO.upper())
    assert not login._eh_acesso_automatizado(PROCURACAO)
    assert not login._eh_acesso_automatizado("")


# ── Onde a politica e usada ────────────────────────────────────────────────

def _fonte(funcao):
    return inspect.getsource(funcao)


def test_garantir_acesso_aceita_o_numero_de_insistencias_e_o_padrao_e_INSISTIR():
    parametro = inspect.signature(login.garantir_acesso_ecac).parameters[
        "insistencias_acesso_automatizado"]
    assert parametro.default is None and parametro.kind is parametro.KEYWORD_ONLY
    assert "INSISTENCIAS_ACESSO_AUTOMATIZADO_NA_TROCA" in _fonte(login.garantir_acesso_ecac)


def test_garantir_acesso_usa_a_politica_e_nao_tem_mais_o_laco_de_2_envios():
    fonte = _fonte(login.garantir_acesso_ecac)
    assert "_enviar_ate_o_desfecho(" in fonte
    assert "MAX_ENVIOS_ALTERAR" not in fonte


def test_o_login_inteiro_tambem_insiste():
    """`main` (o `fazer_login`) chama `garantir_acesso_ecac` sem zerar a
    insistencia: o 1o login de cada certificado tambem nao fecha o navegador
    por causa do "acesso automatizado"."""
    chamadas = [no for no in ast.walk(ast.parse(_fonte(login.main)))
                if isinstance(no, ast.Call) and getattr(no.func, "id", "") == "garantir_acesso_ecac"]
    assert chamadas
    assert all(k.arg != "insistencias_acesso_automatizado" for c in chamadas for k in c.keywords)


def test_a_PAGINA_enviando_conta_como_reacao_e_evita_o_clique():
    """O botao some e o campo esvazia quando o ajax da pagina leva o envio
    (`[diag]` de 27/08/2026). Um clique ai seria o SEGUNDO envio."""
    cliques = []
    via = login._enviar_uma_vez(lambda: "enviando", lambda: cliques.append(1),
                                lambda _ms: None, espera_ms=50, passo_ms=10)
    assert via == "pagina" and cliques == []
    fonte = _fonte(login.garantir_acesso_ecac)
    assert "_formulario_em_envio()" in fonte and '"enviando"' in fonte

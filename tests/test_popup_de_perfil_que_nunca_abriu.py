"""Popup de perfil FECHADO: deu certo, ou nunca abriu?

Execução real de 20/10/2026 (AUT-0013, máquina edge). Login perfeito, captcha
resolvido, redirecionamento concluído — e então:

    Clicando em 'Alterar perfil de acesso'...
    Aguardando popup carregar (formPJ no DOM)...
    Ativando aba 'Pessoa Juridica'...
      -> nenhum seletor de aba bateu (talvez ja esteja ativa).
    Aguardando #txtNIPapel2 ficar visivel...
      -> input nao ficou visivel; vai tentar fallback via JS.
    [diag] inputs do formPJ: [... 'visible': False ... 'visible': False ...]
    Enviando o 'Alterar' (formPJ) — envio 1 de no maximo 2...
      -> [via=pagina] a propria tela enviou o formulario (reacao: ok)
      -> perfil de acesso alterado (via=pagina).

O diálogo nunca apareceu. O que apareceu foi o aviso "o e-CAC será desativado",
na frente do dashboard, e ninguém o fechou — o `<button type="button">Continuar
no e-CAC por enquanto</button>` não tem id nem classe, e a detecção estava
ancorada no id do diálogo.

O erro de leitura: o critério de sucesso era a AUSÊNCIA do diálogo, que é também
o estado antes de ele abrir. A troca foi dada por feita, o eCAC seguiu no perfil
do procurador, as 32 consultas da empresa voltaram vazias e a falha só apareceu
três telas adiante — como "o PER/DCOMP Web não respondeu", que manda investigar
sessão caída.

`#formPJ` está no DOM desde o carregamento da página, então esperar por
`attached` nunca provou nada. O que prova é ele ficar VISÍVEL.

Sem navegador: o que está em jogo é a leitura da tela, não a tela.
"""
from ecac_login import login


# ── O que "fechado" quer dizer ──────────────────────────────────────────────

def test_fechado_depois_de_abrir_e_sucesso():
    """O caminho feliz de sempre: o diálogo apareceu, foi enviado e saiu."""
    assert login._popup_fechado_significa(True) == "ok"


def test_fechado_sem_nunca_abrir_nao_e_sucesso():
    """O caso de 20/10/2026 — e o desfecho tem de ter NOME PRÓPRIO.

    Não basta "não é ok": quem lê o log precisa saber que o diálogo não
    apareceu, porque é na frente do dashboard que está a causa.
    """
    assert login._popup_fechado_significa(False) == "nao_abriu"


# ── A política de envio não engole o "nao_abriu" ────────────────────────────

class _Portal:
    """Portal que responde sempre a mesma coisa, contando os envios."""

    def __init__(self, estado):
        self._estado = estado
        self.envios = 0
        self.reenvios = []

    def enviar(self):
        self.envios += 1
        return "pagina"

    def desfecho(self):
        return self._estado, ""

    def preparar_reenvio(self, motivo):
        self.reenvios.append(motivo)

    def esperar(self, _s):
        pass


def _ate_o_desfecho(portal, **kw):
    kw.setdefault("insistencias", 2)
    return login._enviar_ate_o_desfecho(portal.enviar, portal.desfecho,
                                        portal.preparar_reenvio, portal.esperar,
                                        **kw)


def test_dialogo_que_nao_abre_nao_vira_troca_concluida():
    """O estado sobe inteiro até quem decide, e não é "ok"."""
    portal = _Portal("nao_abriu")
    estado, erro, via = _ate_o_desfecho(portal)
    assert estado == "nao_abriu"
    assert erro == ""


def test_dialogo_que_nao_abre_ganha_uma_segunda_chance():
    """O reenvio reabre o formulário — e é aí que o aviso do e-CAC, agora
    fechado antes de cada tentativa, deixa o diálogo abrir."""
    portal = _Portal("nao_abriu")
    _ate_o_desfecho(portal)
    assert portal.envios == 2
    assert portal.reenvios == ["sem_resposta"]


def test_a_segunda_chance_e_finita():
    """Uma empresa não pode ficar presa reabrindo um diálogo que não abre."""
    portal = _Portal("nao_abriu")
    _ate_o_desfecho(portal, reenvios=3)
    assert portal.envios == 4


def test_troca_que_da_certo_segue_saindo_no_primeiro_envio():
    """Regressão: o caminho feliz não paga nada pela guarda nova."""
    portal = _Portal("ok")
    estado, _, via = _ate_o_desfecho(portal)
    assert estado == "ok"
    assert portal.envios == 1
    assert portal.reenvios == []


# ── O aviso "Continuar no e-CAC por enquanto" ───────────────────────────────

class _Botao:
    def __init__(self, pagina, visivel):
        self._pagina = pagina
        self._visivel = visivel

    @property
    def first(self):
        return self

    def is_visible(self, **_kw):
        return self._visivel

    def wait_for(self, **_kw):
        self._pagina.esperas += 1
        if not self._visivel:
            raise RuntimeError("nao ficou visivel")

    def click(self, **_kw):
        self._pagina.cliques.append("papel")


class _Pagina:
    """Dashboard com (ou sem) o aviso de encerramento na frente."""

    def __init__(self, com_aviso: bool):
        self._com_aviso = com_aviso
        self.cliques = []
        self.esperas = 0
        self.papeis_pedidos = []

    def get_by_role(self, papel, name=None):
        self.papeis_pedidos.append((papel, name))
        return _Botao(self, self._com_aviso)

    def locator(self, _sel):
        return _Botao(self, self._com_aviso)

    def evaluate(self, *_a):
        return None

    def wait_for_timeout(self, _ms):
        pass


def test_o_aviso_e_fechado_pelo_texto_do_botao():
    """O botão é `<button type="button">…</button>`: sem id, sem classe. O texto
    é o que ele tem — e é o que o operador vê."""
    pagina = _Pagina(com_aviso=True)
    assert login._fechar_aviso_de_encerramento(pagina) is True
    assert pagina.cliques == ["papel"]
    assert pagina.papeis_pedidos[0] == ("button", login.TEXTO_CONTINUAR_NO_ECAC)


def test_sem_aviso_na_tela_nada_e_clicado():
    pagina = _Pagina(com_aviso=False)
    assert login._fechar_aviso_de_encerramento(pagina) is False
    assert pagina.cliques == []


def test_a_olhada_por_empresa_nao_espera():
    """Ela roda antes de CADA tentativa de abrir o perfil. Esperar ali seria
    segundos multiplicados pelo lote inteiro — 250 empresas numa planilha."""
    pagina = _Pagina(com_aviso=False)
    login._fechar_aviso_de_encerramento(pagina)
    assert pagina.esperas == 0


def test_depois_do_login_a_olhada_espera_o_aviso_aparecer():
    """`is_visible` devolve o estado do INSTANTE, e o aviso aparece depois do
    dashboard: quem olha uma vez olha antes dele."""
    pagina = _Pagina(com_aviso=True)
    login._fechar_aviso_de_encerramento(pagina, espera_ms=1_000)
    assert pagina.esperas == 1


def test_a_espera_do_aviso_e_curta():
    """Paga uma vez por login, ao lado de dois minutos de certificado e
    captcha — mas não pode crescer sem alguém notar."""
    assert login.ESPERA_AVISO_ENCERRAMENTO_MS <= 5_000

def test_uma_pagina_que_nao_sabe_responder_nao_derruba_o_login():
    """Fechar um aviso cosmetico nao pode ser o motivo de um login falhar.

    A RESOLUCAO do locator tambem entra no `try`, e nao so a espera: foi um
    `page` sem `get_by_role` que levou um `AttributeError` de dentro desta
    funcao para fora, derrubando dois testes do caminho do certificado.
    """
    class _Muda:
        def get_by_role(self, *_a, **_k):
            raise AttributeError("essa pagina nao tem get_by_role")

    assert login._fechar_aviso_de_encerramento(_Muda()) is False


def test_clique_que_estoura_em_todas_as_vias_nao_sobe():
    """Com o aviso na tela e nenhuma via funcionando, segue-se sem ele."""
    class _Travada(_Pagina):
        def __init__(self):
            super().__init__(com_aviso=True)

        def get_by_role(self, papel, name=None):
            self.papeis_pedidos.append((papel, name))
            botao = _Botao(self, True)
            botao.click = lambda **_k: (_ for _ in ()).throw(RuntimeError("nao clicou"))
            return botao

        def locator(self, _sel):
            botao = _Botao(self, True)
            botao.click = lambda **_k: (_ for _ in ()).throw(RuntimeError("nao clicou"))
            return botao

        def evaluate(self, *_a):
            raise RuntimeError("contexto destruido")

    assert login._fechar_aviso_de_encerramento(_Travada()) is True

# ── A ligacao dentro de `garantir_acesso_ecac` ──────────────────────────────
#
# A funcao e grande e cheia de closures que exigem navegador. Quando nao se pode
# driva-la, olha-se a ESTRUTURA dela — e o idioma e o mesmo de
# `test_acesso_automatizado_na_troca`.

def _chamadas_em(nome_da_funcao: str) -> list:
    import ast
    import inspect

    arvore = ast.parse(inspect.getsource(login))
    alvo = next(no for no in ast.walk(arvore)
                if isinstance(no, ast.FunctionDef) and no.name == nome_da_funcao)
    return [no.func.id for no in ast.walk(alvo)
            if isinstance(no, ast.Call) and isinstance(no.func, ast.Name)]


def test_os_dois_lugares_que_leem_popup_fechado_passam_pela_mesma_regra():
    """Eram DOIS: `_reacao_da_tela` (que decide se clica) e `_desfecho` (que
    decide o desfecho). Os dois devolviam "ok" direto, e corrigir um so deixaria
    o outro dando a troca por feita."""
    chamadas = _chamadas_em("garantir_acesso_ecac")
    assert chamadas.count("_popup_fechado_significa") == 2


def test_o_aviso_do_ecac_e_fechado_antes_de_abrir_o_perfil():
    """Uma vez depois do login (com espera) e uma vez por tentativa de abrir o
    dialogo (sem espera): o aviso pode chegar depois do dashboard."""
    chamadas = _chamadas_em("garantir_acesso_ecac")
    assert chamadas.count("_fechar_aviso_de_encerramento") == 2


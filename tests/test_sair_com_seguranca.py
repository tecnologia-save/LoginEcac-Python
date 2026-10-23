"""Sair do eCAC pelo botão, sempre — fechar o Chrome não encerra a sessão.

O certificado tem um número LIMITADO de perfis logados ao mesmo tempo. Fechar o
navegador deixa a sessão de pé do lado da Receita: o perfil continua ocupado até
expirar sozinho, e em poucas execuções não há mais vaga. O relato do operador é
sempre o mesmo — "não entra mais".

O botão é um `<span class="botaoAzul">Sair com Segurança </span>`: sem id, sem
`role`, com espaço sobrando no fim. Texto é o que ele tem.

E ele só existe no portal. A automação termina no PER/DCOMP Web
(`www3.cav.receita.fazenda.gov.br/perdcomp-web`), onde o botão não está — então
voltar para a home e procurar de novo é o caminho NORMAL, não a exceção.

Sem navegador: o que está em jogo é a política de saída, não a tela.
"""
from ecac_login import login

URL_PERDCOMP = "https://www3.cav.receita.fazenda.gov.br/perdcomp-web/#/tela-inicial"
URL_PORTAL = "https://cav.receita.fazenda.gov.br/ecac/Aplicacao.aspx"
URL_GOVBR = "https://sso.acesso.gov.br/login"


class _Alvo:
    def __init__(self, pagina, visivel):
        self._pagina, self._visivel = pagina, visivel

    @property
    def first(self):
        return self

    def wait_for(self, **_kw):
        if not self._visivel():
            raise RuntimeError("nao visivel")

    def click(self, **_kw):
        self._pagina.cliques += 1


class _Pagina:
    """Página do eCAC. O botão de sair só aparece no portal — como no real.

    `botao_no_portal=False` reproduz o portal que carregou sem o botão: é o que
    força o último recurso pelo DOM.
    """

    def __init__(self, url=URL_PERDCOMP, botao_no_portal=True, home_abre=True):
        self.url = url
        self._botao_no_portal = botao_no_portal
        self._home_abre = home_abre
        self.cliques = 0
        self.navegacoes = []
        self.cliques_no_dom = 0
        self.fechada = False

    # ── o que o Playwright oferece ──────────────────────────────────────────
    def _tem_botao(self):
        return self._botao_no_portal and "perdcomp-web" not in self.url

    def get_by_text(self, _texto, **_kw):
        return _Alvo(self, self._tem_botao)

    def locator(self, _sel):
        return _Alvo(self, self._tem_botao)

    def evaluate(self, _script, *_a):
        self.cliques_no_dom += 1
        return self._tem_botao()

    def goto(self, url, **_kw):
        self.navegacoes.append(url)
        if not self._home_abre:
            raise RuntimeError("a home nao abriu")
        self.url = url

    def is_closed(self):
        return self.fechada

    def wait_for_timeout(self, _ms):
        pass


class _Contexto:
    def __init__(self, *paginas):
        self.pages = list(paginas)
        self.fechado = False

    def close(self):
        self.fechado = True


class _Driver:
    def __init__(self):
        self.parado = False

    def stop(self):
        self.parado = True


def _sair(pagina, **kw):
    kw.setdefault("espera_ms", 10)
    return login.sair_com_seguranca(pagina, **kw)


# ── O caminho normal: a automação termina no PER/DCOMP Web ──────────────────

def test_do_perdcomp_web_volta_para_a_home_e_sai():
    """O CAMINHO NORMAL desta automação, e não um caso de exceção."""
    pagina = _Pagina(url=URL_PERDCOMP)

    assert _sair(pagina) is True
    assert pagina.navegacoes == [login.URL_HOME_ECAC]
    assert pagina.cliques == 1


def test_no_portal_sai_sem_navegar():
    """Já estando no portal, não há por que recarregar nada."""
    pagina = _Pagina(url=URL_PORTAL)

    assert _sair(pagina) is True
    assert pagina.navegacoes == []
    assert pagina.cliques == 1


def test_a_home_e_exatamente_a_pedida():
    """A URL é a do pedido, não uma parecida."""
    assert login.URL_HOME_ECAC == "https://cav.receita.fazenda.gov.br/ecac/#"


def test_o_texto_do_botao_e_o_do_span():
    assert login.TEXTO_SAIR_COM_SEGURANCA == "Sair com Segurança"


# ── Quando não dá para sair ─────────────────────────────────────────────────

def test_home_que_nao_abre_nao_levanta():
    """Falhar na saída não pode virar exceção sobre um trabalho que já acabou —
    mas o log tem de dizer, porque a sessão fica ocupada."""
    pagina = _Pagina(url=URL_PERDCOMP, home_abre=False)

    assert _sair(pagina) is False
    assert pagina.cliques == 0


def test_botao_ausente_na_home_tenta_pelo_dom_e_desiste():
    """O último recurso é o clique pelo DOM, que não depende de ponteiro. Sem
    ele também, desiste — sem derrubar nada."""
    pagina = _Pagina(url=URL_PORTAL, botao_no_portal=False)

    assert _sair(pagina) is False
    assert pagina.cliques_no_dom >= 1


# ── O funil: todo encerramento passa por `encerrar_sessao` ──────────────────

def test_encerrar_sessao_sai_antes_de_fechar():
    """A saída vive no funil de propósito: é por onde passam o fim normal, o
    caminho de falha de `main` e o teardown de quem chamou. Pendurá-la em cada
    um seria garantir que um ficasse de fora — e um de fora é perfil ocupado."""
    pagina = _Pagina(url=URL_PERDCOMP)
    contexto, driver = _Contexto(pagina), _Driver()

    login.encerrar_sessao(driver, contexto)

    assert pagina.cliques == 1
    assert contexto.fechado and driver.parado


def test_fora_do_ecac_nao_tenta_sair():
    """Login que morreu no gov.br não tem sessão para encerrar: tentar seria
    pagar uma navegação e duas esperas em cada falha de login."""
    pagina = _Pagina(url=URL_GOVBR)
    contexto = _Contexto(pagina)

    login.encerrar_sessao(_Driver(), contexto)

    assert pagina.cliques == 0
    assert pagina.navegacoes == []
    assert contexto.fechado


def test_so_a_primeira_aba_que_sai_e_suficiente():
    """Sair encerra a sessão no servidor: a segunda aba não precisa repetir."""
    uma, outra = _Pagina(url=URL_PORTAL), _Pagina(url=URL_PORTAL)
    login.encerrar_sessao(_Driver(), _Contexto(uma, outra))

    assert (uma.cliques, outra.cliques) == (1, 0)


def test_aba_fechada_e_ignorada():
    viva = _Pagina(url=URL_PORTAL)
    morta = _Pagina(url=URL_PORTAL)
    morta.fechada = True

    login.encerrar_sessao(_Driver(), _Contexto(morta, viva))

    assert viva.cliques == 1
    assert morta.cliques == 0


def test_saida_que_explode_ainda_fecha_o_navegador():
    """Chrome vivo é pior do que sessão ocupada: um some em minutos, o outro
    trava a próxima execução."""
    class _Explode(_Pagina):
        def get_by_text(self, *_a, **_k):
            raise RuntimeError("contexto destruido")

        def locator(self, *_a, **_k):
            raise RuntimeError("contexto destruido")

        def evaluate(self, *_a):
            raise RuntimeError("contexto destruido")

        def goto(self, *_a, **_k):
            raise RuntimeError("contexto destruido")

    contexto, driver = _Contexto(_Explode(url=URL_PORTAL)), _Driver()
    login.encerrar_sessao(driver, contexto)

    assert contexto.fechado and driver.parado


def test_contexto_sem_abas_nao_atrapalha():
    contexto, driver = _Contexto(), _Driver()
    login.encerrar_sessao(driver, contexto)
    assert contexto.fechado and driver.parado


def test_encerrar_sessao_continua_idempotente():
    """Chamar duas vezes não pode virar erro: o teardown da execução e o caminho
    de falha de quem lançou alcançam a mesma sessão."""
    pagina = _Pagina(url=URL_PORTAL)
    contexto, driver = _Contexto(pagina), _Driver()

    login.encerrar_sessao(driver, contexto)
    login.encerrar_sessao(driver, contexto)   # não levanta

    assert contexto.fechado


def test_sair_pode_ser_desligado():
    """Para quem SABE que não há sessão — teste, ou sessão que o portal já
    encerrou."""
    pagina = _Pagina(url=URL_PORTAL)
    login.encerrar_sessao(_Driver(), _Contexto(pagina), sair=False)
    assert pagina.cliques == 0

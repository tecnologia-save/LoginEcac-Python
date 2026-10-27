"""O PKCS#12 legado da AC brasileira e o OpenSSL 3 do Node — NORMATIVO.

O CASO REAL (27/10/2026, AUT-0013, duas maquinas, cinco execucoes seguidas):
o lancamento morria em menos de um segundo depois de "Lancando Chrome...",
sempre com o mesmo desfecho no log da plataforma — `falha=Error`.

    Error: BrowserType.launch_persistent_context: Failed to load client
    certificate: Unsupported TLS certificate. Most likely, the security
    algorithm of the given certificate was deprecated by OpenSSL.

Quem apresenta o certificado nao e o Chrome: e o Node do Playwright, que
intercepta o TLS e monta o contexto seguro com o OpenSSL 3 dele. Comparando a
ESTRUTURA de dois certificados reais do mesmo Cofre (sem decifrar nada):

    o que funcionava:  PBES2 / PBKDF2-SHA256 / AES-256-CBC, MAC SHA-256
    o que falhava:     pbeWithSHAAnd40BitRC2-CBC nos certificados,
                       pbeWithSHAAnd3-KeyTripleDES-CBC na chave, MAC SHA-1

A conferencia previa de quem chama abre os dois sem reclamar — o `cryptography`
le cifra legada —, e por isso o arquivo chegava intacto ate o lancamento.

O que estes testes fecham: o PFX e REEMPACOTADO em AES-256 antes de ir para o
Playwright, o par chave+certificado atravessa a conversao sem mudar, e nada
disso vira um jeito novo de falhar — o que nao der para converter segue pelo
caminho de sempre.

Dados sinteticos: certificado autoassinado gerado na hora, senha de teste.
A cifra de ENTRADA e a legada que o `cryptography` sabe escrever (3DES); o RC2
do caso real nao tem como ser gerado aqui, e o que estes testes travam e a
SAIDA ser moderna e a identidade ser preservada.
"""
import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    pkcs12,
)

from ecac_login import login
from ecac_login.login import (
    CERT_ORIGINS,
    _build_client_certificates,
    _montar_launch_kwargs,
    _pkcs12_moderno,
)

SENHA = "senha-sintetica"

# OIDs lidos direto do DER, em TLV. O `AlgorithmIdentifier` do PKCS#12 fica EM
# CLARO no arquivo, então dá para afirmar com que cifra ele foi escrito sem
# precisar da senha.
OID_PBES2 = bytes.fromhex("06092A864886F70D01050D")
OID_AES256_CBC = bytes.fromhex("060960864801650304012A")
OID_3DES_LEGADO = bytes.fromhex("060A2A864886F70D010C0103")
OID_RC2_40_LEGADO = bytes.fromhex("060A2A864886F70D010C0106")


def _par():
    """Um par chave+certificado autoassinado, novo a cada chamada."""
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nome = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME,
                                         "EMPRESA SINTETICA LTDA")])
    agora = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(nome).issuer_name(nome)
            .public_key(chave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(agora - datetime.timedelta(days=1))
            .not_valid_after(agora + datetime.timedelta(days=365))
            .sign(chave, hashes.SHA256()))
    return chave, cert


def _legado(tmp_path, nome="legado.pfx"):
    """Um `.pfx` com a cifra LEGADA que o `cryptography` sabe escrever."""
    chave, cert = _par()
    cifra = (PrivateFormat.PKCS12.encryption_builder()
             .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
             .hmac_hash(hashes.SHA1())
             .build(SENHA.encode()))
    caminho = tmp_path / nome
    caminho.write_bytes(pkcs12.serialize_key_and_certificates(
        b"sintetico", chave, cert, None, cifra))
    return caminho, chave, cert


# ── A conversão ──────────────────────────────────────────────────────────────

def test_o_arquivo_legado_sai_em_pbes2_aes256(tmp_path):
    """A SAÍDA é o que importa: é ela que o OpenSSL 3 do Node vai abrir."""
    caminho, _, _ = _legado(tmp_path)
    assert OID_3DES_LEGADO in caminho.read_bytes(), "a entrada não é legada"

    convertido = _pkcs12_moderno(caminho, SENHA)

    assert convertido is not None
    assert OID_PBES2 in convertido
    assert OID_AES256_CBC in convertido
    assert OID_3DES_LEGADO not in convertido
    assert OID_RC2_40_LEGADO not in convertido


def test_a_conversao_preserva_o_certificado_e_a_chave(tmp_path):
    """O certificado não muda — muda o empacotamento do arquivo.

    Se a identidade mudasse, o handshake mTLS passaria a ser feito com outra
    coisa, e o portal recusaria o acesso em vez de o lançamento falhar: um
    defeito mais silencioso do que o que se está consertando.
    """
    caminho, chave, cert = _legado(tmp_path)

    nova_chave, novo_cert, cadeia = pkcs12.load_key_and_certificates(
        _pkcs12_moderno(caminho, SENHA), SENHA.encode())

    assert novo_cert.public_bytes(Encoding.DER) == cert.public_bytes(Encoding.DER)
    assert (nova_chave.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            == chave.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
    assert cadeia == []


def test_a_senha_continua_sendo_a_mesma(tmp_path):
    """A `passphrase` segue indo para o Playwright como veio, então o arquivo
    convertido tem de abrir com ela — e não com outra."""
    caminho, _, _ = _legado(tmp_path)
    convertido = _pkcs12_moderno(caminho, SENHA)

    with pytest.raises(Exception):
        pkcs12.load_key_and_certificates(convertido, b"outra-senha")
    assert pkcs12.load_key_and_certificates(convertido, SENHA.encode())[0]


# ── O que NÃO converte segue pelo caminho de antes ───────────────────────────

def test_arquivo_ausente_nao_converte(tmp_path):
    assert _pkcs12_moderno(tmp_path / "nao_existe.pfx", SENHA) is None


def test_arquivo_que_nao_e_pfx_nao_converte(tmp_path):
    qualquer = tmp_path / "qualquer.pfx"
    qualquer.write_bytes(b"isto nao e um PKCS#12")
    assert _pkcs12_moderno(qualquer, SENHA) is None


def test_senha_errada_nao_converte(tmp_path):
    """Não é aqui que se decide senha errada: quem chama já confere o `.pfx` e
    tem mensagem própria para isso. Aqui só não se converte."""
    caminho, _, _ = _legado(tmp_path)
    assert _pkcs12_moderno(caminho, "senha-que-nao-abre") is None


def test_pfx_sem_chave_privada_nao_converte(tmp_path):
    """`load_key_and_certificates` devolve `(None, None, [ca])` sem levantar
    para um PKCS#12 que carrega só certificado — e não há o que reempacotar."""
    _, cert = _par()
    so_cert = tmp_path / "so_cert.pfx"
    so_cert.write_bytes(pkcs12.serialize_key_and_certificates(
        b"sintetico", None, None, [cert],
        PrivateFormat.PKCS12.encryption_builder().build(SENHA.encode())))
    assert _pkcs12_moderno(so_cert, SENHA) is None


@pytest.mark.parametrize("senha", [None, ""])
def test_sem_senha_nao_converte(tmp_path, senha):
    """Sem senha não há como reencriptar mantendo o contrato — e um PFX que
    abre sem senha é um PFX que o Playwright já abre."""
    caminho, _, _ = _legado(tmp_path)
    assert _pkcs12_moderno(caminho, senha) is None


# ── Como o arquivo convertido chega ao navegador ─────────────────────────────

def test_o_convertido_vai_em_memoria_e_o_caminho_nao_e_usado():
    """`pfx` em bytes existe na API justamente para isto: a chave convertida
    vive no processo e não vira arquivo em disco."""
    certificados = _build_client_certificates(
        "C:/sintetico/certificado.pfx", SENHA, b"PFX-CONVERTIDO")

    assert len(certificados) == len(CERT_ORIGINS)
    assert all(c["pfx"] == b"PFX-CONVERTIDO" for c in certificados)
    assert all("pfxPath" not in c for c in certificados)
    assert all(c["passphrase"] == SENHA for c in certificados)


def test_sem_conversao_o_pfxpath_continua_como_sempre_foi():
    """A retrocompatibilidade do caminho de falha: nada converteu, nada muda."""
    certificados = _build_client_certificates(
        "C:/sintetico/certificado.pfx", SENHA, None)

    assert all(c["pfxPath"] == "C:/sintetico/certificado.pfx"
               for c in certificados)
    assert all("pfx" not in c for c in certificados)


def test_os_kwargs_do_chrome_levam_o_convertido():
    k = _montar_launch_kwargs("perfil", cert_pfx_path="C:/sintetico/c.pfx",
                              cert_pfx_passphrase=SENHA,
                              cert_pfx_bytes=b"PFX-CONVERTIDO")
    assert all(c["pfx"] == b"PFX-CONVERTIDO" for c in k["client_certificates"])


def test_montar_kwargs_continua_puro(tmp_path):
    """A leitura do arquivo mora em `_pkcs12_moderno`, e isto é o que mantém a
    configuração do navegador conferível sem Chrome e sem certificado: montar
    os kwargs com um caminho que NÃO EXISTE não pode nem tocar o disco."""
    k = _montar_launch_kwargs("perfil",
                              cert_pfx_path=str(tmp_path / "nao_existe.pfx"),
                              cert_pfx_passphrase=SENHA)
    assert "client_certificates" in k
    assert list(tmp_path.iterdir()) == []
# -- O caminho completo do `main` -------------------------------------------

class _ContextoFalso:
    """O que `launch_persistent_context` devolve. Nao abre nada."""

    def __init__(self):
        self.pages = []
        self.fechado = False

    def new_page(self):
        pagina = object()
        self.pages.append(pagina)
        return pagina

    def close(self):
        self.fechado = True


class _PlaywrightFalso:
    """Driver dublado: registra os kwargs do lancamento e se foi parado."""

    def __init__(self, registro, erro=None):
        self._registro = registro
        self._erro = erro
        self.parado = False
        self.chromium = self

    def start(self):
        return self

    def stop(self):
        self.parado = True

    def launch_persistent_context(self, **kwargs):
        self._registro.append(kwargs)
        if self._erro is not None:
            raise self._erro
        return _ContextoFalso()


@pytest.fixture
def driver_falso(monkeypatch):
    """Substitui o `sync_playwright` do modulo. Nenhum Chrome e aberto."""
    def montar(erro=None):
        registro = []
        falso = _PlaywrightFalso(registro, erro)
        monkeypatch.setattr(login, "sync_playwright", lambda: falso)
        monkeypatch.setattr(login, "garantir_acesso_ecac", lambda *a, **k: True)
        return falso, registro
    return montar


def test_o_login_entrega_ao_chrome_o_pfx_reempacotado(tmp_path, driver_falso):
    """O caminho de ponta a ponta: o arquivo legado do Cofre entra, e o que
    chega ao navegador e AES-256, em memoria."""
    caminho, _, _ = _legado(tmp_path, "para_o_login.pfx")
    _, registro = driver_falso()

    login.main(cnpj="00000000000000", project_dir=tmp_path,
               cert_pfx_path=str(caminho), cert_pfx_passphrase=SENHA)

    certificados = registro[0]["client_certificates"]
    assert all("pfxPath" not in c for c in certificados)
    assert OID_PBES2 in certificados[0]["pfx"]
    assert OID_3DES_LEGADO not in certificados[0]["pfx"]


def test_lancamento_que_falha_nao_deixa_driver_orfao(tmp_path, driver_falso):
    """`sync_playwright().start()` sobe um processo Node ANTES do lancamento.

    MEDIDO em 27/10/2026: sem o `stop()` o driver sobrevive a falha do
    lancamento e so morre junto com o processo que o abriu. Nao fica orfao na
    maquina — fica vivo ate o fim da execucao, e numa run de muitas empresas e
    um Node acumulado por lancamento recusado (certificado que o OpenSSL nao
    aceita, Chrome ausente, perfil em uso). Quem lanca fecha, inclusive quando
    o lancamento falha.
    """
    class _LancamentoRecusado(Exception):
        pass

    falso, _ = driver_falso(erro=_LancamentoRecusado("Unsupported TLS certificate"))

    with pytest.raises(_LancamentoRecusado):
        login.main(cnpj="00000000000000", project_dir=tmp_path)

    assert falso.parado, "o processo Node do driver sobreviveu a falha"

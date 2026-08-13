"""Configuracao de certificado do login no eCAC — NORMATIVO.

Primeira suite deste repositorio. Cobre a unica coisa que a extensao de API
introduziu: COMO o certificado chega ao Chrome, e a garantia de que os dois
mecanismos nunca ficam ativos ao mesmo tempo.

  MODO PFX    cert_pfx_path informado -> client_certificates presente e a flag
              --auto-select-certificate-for-urls AUSENTE.
  MODO STORE  cert_pfx_path ausente   -> comportamento atual do desktop, com a
              flag presente e sem client_certificates.

Quem escolhe o modo e a PRESENCA de `cert_pfx_path`, nunca a senha: se a
passphrase decidisse, um pedido explicito de PFX viraria modo Store em silencio.

Sem Chrome: `_montar_launch_kwargs` e pura, entao a configuracao e verificavel
sem abrir navegador. Dados sinteticos — nenhum certificado, senha, CNPJ ou
caminho pessoal real.
"""
import inspect
import subprocess
import sys
from pathlib import Path

import pytest

import ecac_login
from ecac_login.login import (
    CERT_ORIGINS,
    CertificadoInvalido,
    _montar_launch_kwargs,
)

RAIZ = Path(__file__).resolve().parent.parent

PFX = "C:/sintetico/certificado.pfx"
SENHA = "senha-sintetica"
CN = "EMPRESA SINTETICA LTDA"

FLAG_AUTO_SELECT = "--auto-select-certificate-for-urls"


def _tem_auto_select(kwargs) -> bool:
    return any(a.startswith(FLAG_AUTO_SELECT) for a in kwargs["args"])


# ── 1 · Modo PFX ─────────────────────────────────────────────────────────────

def test_pfx_explicito_monta_client_certificates():
    k = _montar_launch_kwargs("perfil", cert_pfx_path=PFX, cert_pfx_passphrase=SENHA)
    certs = k["client_certificates"]
    assert len(certs) == len(CERT_ORIGINS)
    assert {c["origin"] for c in certs} == set(CERT_ORIGINS)
    assert all(c["pfxPath"] == PFX for c in certs)
    assert all(c["passphrase"] == SENHA for c in certs)


def test_pfx_explicito_desliga_o_auto_select():
    """A flag nao pode nem aparecer: filtro vazio significaria 'primeiro
    certificado disponivel do Windows Store'."""
    k = _montar_launch_kwargs("perfil", cert_pfx_path=PFX, cert_pfx_passphrase=SENHA)
    assert not _tem_auto_select(k)


def test_pfx_cobre_a_origem_do_handshake():
    """`client_certificates` casa por origem EXATA, sem wildcard."""
    k = _montar_launch_kwargs("perfil", cert_pfx_path=PFX, cert_pfx_passphrase=SENHA)
    origens = {c["origin"] for c in k["client_certificates"]}
    assert "https://certificado.sso.acesso.gov.br" in origens


# ── 2 · Modo Store (desktop legado) ──────────────────────────────────────────

def test_sem_pfx_mantem_o_comportamento_do_desktop(monkeypatch):
    monkeypatch.delenv("CERT_SUBJECT_CN", raising=False)
    k = _montar_launch_kwargs("perfil")
    assert "client_certificates" not in k
    assert _tem_auto_select(k)


def test_sem_pfx_preserva_o_cn_do_ambiente(monkeypatch):
    monkeypatch.setenv("CERT_SUBJECT_CN", CN)
    k = _montar_launch_kwargs("perfil")
    flag = next(a for a in k["args"] if a.startswith(FLAG_AUTO_SELECT))
    assert CN in flag


def test_sem_pfx_cn_explicito_tem_prioridade_sobre_o_ambiente(monkeypatch):
    monkeypatch.setenv("CERT_SUBJECT_CN", "CN-DO-AMBIENTE")
    k = _montar_launch_kwargs("perfil", cert_subject_cn=CN)
    flag = next(a for a in k["args"] if a.startswith(FLAG_AUTO_SELECT))
    assert CN in flag
    assert "CN-DO-AMBIENTE" not in flag


def test_argumentos_base_do_chrome_preservados():
    """O restante da configuracao nao muda em nenhum dos modos."""
    for k in (_montar_launch_kwargs("perfil"),
              _montar_launch_kwargs("perfil", cert_pfx_path=PFX)):
        assert "--start-maximized" in k["args"]
        assert "--remote-debugging-port=9222" in k["args"]
        assert k["channel"] == "chrome"
        assert k["headless"] is False
        assert k["user_data_dir"] == "perfil"


# ── 3, 4, 5 · Precedencia: PFX vence, e nada residual reativa o Store ────────

def test_pfx_vence_cert_subject_cn_residual_no_ambiente(monkeypatch):
    monkeypatch.setenv("CERT_SUBJECT_CN", CN)
    k = _montar_launch_kwargs("perfil", cert_pfx_path=PFX, cert_pfx_passphrase=SENHA)
    assert "client_certificates" in k
    assert not _tem_auto_select(k)
    assert not any(CN in a for a in k["args"])


def test_pfx_vence_cert_subject_cn_explicito(monkeypatch):
    monkeypatch.delenv("CERT_SUBJECT_CN", raising=False)
    k = _montar_launch_kwargs("perfil", cert_pfx_path=PFX,
                              cert_pfx_passphrase=SENHA, cert_subject_cn=CN)
    assert "client_certificates" in k
    assert not _tem_auto_select(k)
    assert not any(CN in a for a in k["args"])


def test_cert_serial_residual_nao_reativa_o_store(monkeypatch):
    """`cert_serial` so alimenta o fallback pywinauto do modo Store; no modo PFX
    nao pode ter efeito algum sobre a configuracao do navegador."""
    monkeypatch.delenv("CERT_SUBJECT_CN", raising=False)
    assinatura = inspect.signature(ecac_login.fazer_login)
    assinatura.bind(cnpj="00", cert_serial="SERIAL-SINTETICO", cert_pfx_path=PFX)
    k = _montar_launch_kwargs("perfil", cert_pfx_path=PFX, cert_pfx_passphrase=SENHA)
    assert "client_certificates" in k
    assert not _tem_auto_select(k)


def test_os_dois_mecanismos_nunca_coexistem(monkeypatch):
    monkeypatch.setenv("CERT_SUBJECT_CN", CN)
    for kwargs in ({}, {"cert_subject_cn": CN},
                   {"cert_pfx_path": PFX},
                   {"cert_pfx_path": PFX, "cert_subject_cn": CN}):
        k = _montar_launch_kwargs("perfil", **kwargs)
        assert ("client_certificates" in k) != _tem_auto_select(k)


# ── 6 · Caminho vazio nao pode virar Store em silencio ───────────────────────

@pytest.mark.parametrize("vazio", ["", "   "])
def test_pfx_vazio_falha_em_vez_de_cair_para_o_store(vazio):
    with pytest.raises(CertificadoInvalido):
        _montar_launch_kwargs("perfil", cert_pfx_path=vazio, cert_pfx_passphrase=SENHA)


# ── Passphrase: a senha NAO decide o modo ────────────────────────────────────

@pytest.mark.parametrize("senha", [None, "", SENHA])
def test_passphrase_nao_decide_o_modo(senha):
    """None, vazia ou preenchida: o modo PFX continua sendo PFX, e o valor e
    repassado como veio (a API aceita `str | None`)."""
    k = _montar_launch_kwargs("perfil", cert_pfx_path=PFX, cert_pfx_passphrase=senha)
    assert "client_certificates" in k
    assert not _tem_auto_select(k)
    assert all(c["passphrase"] == senha for c in k["client_certificates"])


# ── 7 · Retrocompatibilidade dos callers existentes ──────────────────────────

def test_chamada_atual_do_desktop_continua_valida():
    """Assinatura exercitada sem executar: a chamada de hoje precisa continuar
    ligando sem alteracao alguma."""
    inspect.signature(ecac_login.fazer_login).bind(
        cnpj="CNPJ-SINTETICO",      # so a assinatura e exercitada, nunca executada
        project_dir="/tmp/sintetico",
        policy_ok=True,
        cert_serial="",
    )


def test_parametros_novos_sao_keyword_only_e_opcionais():
    parametros = inspect.signature(ecac_login.fazer_login).parameters
    for nome in ("cert_pfx_path", "cert_pfx_passphrase", "cert_subject_cn"):
        p = parametros[nome]
        assert p.kind is inspect.Parameter.KEYWORD_ONLY
        assert p.default is None


def test_ordem_dos_parametros_existentes_preservada():
    nomes = list(inspect.signature(ecac_login.fazer_login).parameters)
    assert nomes[:5] == ["cnpj", "project_dir", "metrics", "policy_ok", "cert_serial"]


# ── 8 · Import safety ────────────────────────────────────────────────────────

def test_importar_nao_abre_navegador_nem_escreve(tmp_path):
    """Import roda em CWD temporario: nada pode ser criado nele."""
    r = subprocess.run(
        [sys.executable, "-c",
         "import ecac_login, ecac_login.login  # noqa: F401\nprint('OK')\n"],
        cwd=str(tmp_path), capture_output=True, text=True, timeout=120,
        check=False, env={**__import__("os").environ, "PYTHONPATH": str(RAIZ)},
    )
    assert r.returncode == 0, r.stderr
    assert "OK" in r.stdout
    assert list(tmp_path.iterdir()) == []

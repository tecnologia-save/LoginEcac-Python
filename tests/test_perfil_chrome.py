"""Onde o perfil do Chrome e criado.

Rodar o .exe de DENTRO do Google Drive punha o perfil no Drive e o Chrome
travava/caia depois de alguns documentos. `dir_perfil_chrome` so mantem o perfil
ao lado do projeto num disco local de verdade.
"""
import os
from pathlib import Path

from ecac_login import login
from ecac_login.login import dir_perfil_chrome, disco_local_confiavel


def test_argumento_explicito_vence(monkeypatch):
    monkeypatch.setenv("ECAC_PERFIL_DIR", "D:/do_ambiente")
    assert dir_perfil_chrome("G:/Meu Drive/robo", "E:/do_argumento") == Path("E:/do_argumento")


def test_variavel_de_ambiente_vence_a_deteccao(monkeypatch):
    monkeypatch.setenv("ECAC_PERFIL_DIR", "D:/do_ambiente")
    monkeypatch.setattr(login, "disco_local_confiavel", lambda _c: True)
    assert dir_perfil_chrome("C:/projeto") == Path("D:/do_ambiente")


def test_disco_local_mantem_o_perfil_ao_lado_do_projeto(monkeypatch):
    monkeypatch.delenv("ECAC_PERFIL_DIR", raising=False)
    monkeypatch.setattr(login, "disco_local_confiavel", lambda _c: True)
    assert dir_perfil_chrome("C:/projeto") == Path("C:/projeto") / "chrome_debug_profile"


def test_fora_do_disco_local_vai_para_localappdata(monkeypatch, tmp_path):
    monkeypatch.delenv("ECAC_PERFIL_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(login, "disco_local_confiavel", lambda _c: False)
    perfil = dir_perfil_chrome("G:/Meu Drive/Robô Ressarcimento")
    assert perfil.name == "chrome_debug_profile"  # nome usado para achar o Chrome
    assert perfil.parent.parent == tmp_path / "SaveEcac" / "perfis"
    assert perfil.parent.name.startswith("Rob_Ressarcimento-")


def test_projetos_de_mesmo_nome_nao_dividem_perfil(monkeypatch, tmp_path):
    monkeypatch.delenv("ECAC_PERFIL_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(login, "disco_local_confiavel", lambda _c: False)
    assert dir_perfil_chrome("G:/a/robo") != dir_perfil_chrome("H:/b/robo")


def test_disco_do_sistema_e_local():
    assert disco_local_confiavel(os.environ.get("SystemDrive", "C:") + chr(92)) is True


def test_unidade_inexistente_nao_e_local():
    livres = [f"{c}:" for c in "QRSTUVWXYZ" if not os.path.exists(f"{c}:" + chr(92))]
    assert livres, "nenhuma letra livre para o teste"
    assert disco_local_confiavel(livres[-1] + chr(92) + "qualquer") is False


def test_caminho_de_rede_nao_e_local():
    unc = chr(92) * 2 + chr(92).join(["servidor", "compartilhado", "robo"])
    assert disco_local_confiavel(unc) is False

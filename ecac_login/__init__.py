from .login import (
    AcessoBloqueado,
    DispositivosMaximo,
    LoginCancelado,
    PortalIndisponivel,
    registrar_gate,
    abrir_browser_com_certificado,
    encerrar_sessao,
    garantir_acesso_ecac,
    tentou_trocar_perfil,
    ultima_recusa_de_perfil,
)
from .login import main as fazer_login

# `fazer_login` CRIA a sessao (standalone). `garantir_acesso_ecac` opera numa
# sessao existente e nao fecha nada — e o que permite a uma execucao que ja
# passou pelo Servicos RF chegar ao eCAC sem lancar outro Chrome.
__all__ = ["AcessoBloqueado", "DispositivosMaximo", "LoginCancelado",
           "PortalIndisponivel",
           "abrir_browser_com_certificado",
           "encerrar_sessao", "fazer_login", "garantir_acesso_ecac",
           "ultima_recusa_de_perfil", "registrar_gate",
           "tentou_trocar_perfil"]
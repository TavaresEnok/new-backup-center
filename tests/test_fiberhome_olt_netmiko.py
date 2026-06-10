import importlib
import pathlib
import sys


SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "scripts" / "backup_scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

fiberhome = importlib.import_module("fiberhome_olt_netmiko")


def test_fiberhome_session_start_failure_is_reported_as_collection_session_issue():
    exc = RuntimeError(
        "Nao foi possivel iniciar sessao Telnet. Resposta: Trying 128.201.156.114... "
        "tempo esgotado aguardando resposta do equipamento"
    )

    message = fiberhome._human_failure_message(exc)

    assert message.startswith("Nao foi possivel iniciar a sessao de coleta Telnet.")
    assert "porta respondeu no precheck" in message
    assert "Falha inesperada" not in message
    assert fiberhome._classify_failure(exc) == "SCRIPT"


def test_fiberhome_auth_failure_is_reported_as_authentication_issue():
    exc = RuntimeError("Falha na autenticacao Telnet. Resposta: ************* \x1b[73CMaster Bad UserName or Bad Password")

    message = fiberhome._human_failure_message(exc)

    assert message.startswith("Falha de autenticacao")
    assert "\x1b" not in message
    assert "********" not in message
    assert fiberhome._classify_failure(exc) == "AUTENTICACAO"


def test_fiberhome_netmiko_auth_failure_stops_before_interactive_collection(monkeypatch, tmp_path):
    emitted = []

    class FakeLogger:
        def __init__(self, *_args, **_kwargs):
            pass

        def emit(self, message, level="info", *_args, **_kwargs):
            emitted.append((str(message), level))

    class FailingConnectHandler:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            raise RuntimeError("NetmikoAuthenticationException: Login failed: 128.201.156.114")

        def __exit__(self, *_args):
            return False

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("interactive fallback should not run after authentication failure")

    monkeypatch.setattr(fiberhome, "_test_tcp_connect", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(fiberhome, "ConnectHandler", FailingConnectHandler)
    monkeypatch.setattr(fiberhome, "_collect_telnet_with_pexpect", fail_if_called)
    monkeypatch.setattr(fiberhome, "prepare_backup_path", lambda *_args, **_kwargs: str(tmp_path / "fiberhome.cfg"))
    monkeypatch.setattr(fiberhome, "BackupLogger", FakeLogger)

    result = fiberhome.realizar_backup(
        ip="128.201.156.114",
        usuario="admin",
        porta=23,
        nome_provedor="Provedor",
        nome_tipo_equip="OLT FiberHome",
        nome_dispositivo="OLT- FIBERHOME-JAGUARANA",
        parametros={"password": "secret", "use_telnet": True},
    )

    assert result[0] is False
    assert result[3] == "AUTENTICACAO"
    assert "Falha de autenticacao" in result[1]
    assert not (tmp_path / "fiberhome.cfg").exists()
    assert any("Etapa 1.2/4: Abrindo sessao" in msg for msg, _level in emitted)
    assert not any("Etapa 2/4" in msg for msg, _level in emitted)
    assert not any("Etapa 3/4" in msg for msg, _level in emitted)

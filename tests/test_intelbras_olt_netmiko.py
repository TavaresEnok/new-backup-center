import importlib
import pathlib
import sys

from app.services.backup_executor import _supports_protocol_fallback


SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "scripts" / "backup_scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

intelbras_olt_netmiko = importlib.import_module("intelbras_olt_netmiko")


class FakeConnection:
    def __init__(self, kwargs, recorder):
        self.kwargs = kwargs
        self.recorder = recorder

    def __enter__(self):
        self.recorder.append(self.kwargs)
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def find_prompt(self):
        return "OLT#"

    def send_command(self, *_args, **_kwargs):
        return "terminal length 0\r\nOLT#"

    def send_command_timing(self, command, **_kwargs):
        return f"{command}\ninterface gpon 0/1\n onu add 1\n vlan 100\n" + ("x" * 120)


def test_intelbras_olt_uses_ssh_when_use_telnet_is_false(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "ConnectHandler",
        lambda **kwargs: FakeConnection(kwargs, calls),
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "prepare_backup_path",
        lambda *_args, **_kwargs: str(tmp_path / "backup.cfg"),
    )

    result = intelbras_olt_netmiko.realizar_backup(
        ip="10.0.0.1",
        usuario="admin",
        porta=22,
        nome_provedor="Tenant",
        nome_tipo_equip="OLT Intelbras",
        nome_dispositivo="Intelbras OLT SSH",
        parametros={"password": "secret", "use_telnet": False},
    )

    assert result[0] is True
    assert len(calls) == 2
    assert all(call["device_type"] == "cisco_ios" for call in calls)
    assert (tmp_path / "backup.cfg").exists()


class FakeChild:
    pass


def test_intelbras_olt_uses_telnet_when_requested(monkeypatch, tmp_path):
    calls = []
    fake_child = FakeChild()
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "open_pexpect_session",
        lambda command, **kwargs: calls.append((command, kwargs)) or fake_child,
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "_open_and_login",
        lambda child, *_args, **_kwargs: "OLT#",
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "_disable_pagination",
        lambda child: None,
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "_send_collect",
        lambda child, command, **_kwargs: (True, f"{command}\ninterface gpon 0/1\n onu add 1\n vlan 100\n" + ("x" * 120)),
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "close_pexpect_session",
        lambda _child: None,
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "prepare_backup_path",
        lambda *_args, **_kwargs: str(tmp_path / "backup_telnet.cfg"),
    )

    result = intelbras_olt_netmiko.realizar_backup(
        ip="10.0.0.2",
        usuario="admin",
        porta=23,
        nome_provedor="Tenant",
        nome_tipo_equip="OLT Intelbras",
        nome_dispositivo="Intelbras OLT Telnet",
        parametros={"password": "secret", "use_telnet": True},
    )

    assert result[0] is True
    assert len(calls) == 2
    assert calls[0][0] == "telnet 10.0.0.2 23"
    assert calls[1][0] == "telnet 10.0.0.2 23"
    assert (tmp_path / "backup_telnet.cfg").exists()


def test_intelbras_olt_telnet_tries_enable_when_prompt_requires(monkeypatch, tmp_path):
    enable_calls = []
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "open_pexpect_session",
        lambda *_args, **_kwargs: FakeChild(),
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "_open_and_login",
        lambda *_args, **_kwargs: "OLT>",
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "_enter_enable",
        lambda _child, secrets, **_kwargs: enable_calls.append(list(secrets)),
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "_disable_pagination",
        lambda _child: None,
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "_send_collect",
        lambda _child, command, **_kwargs: (True, f"{command}\ninterface gpon 0/1\n onu add 1\n vlan 100\n" + ("x" * 120)),
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "close_pexpect_session",
        lambda _child: None,
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "prepare_backup_path",
        lambda *_args, **_kwargs: str(tmp_path / "backup_enable.cfg"),
    )

    result = intelbras_olt_netmiko.realizar_backup(
        ip="10.0.0.3",
        usuario="admin",
        porta=23,
        nome_provedor="Tenant",
        nome_tipo_equip="OLT Intelbras",
        nome_dispositivo="Intelbras OLT Enable",
        parametros={"password": "secret", "enable_password": "enable-secret", "use_telnet": True},
    )

    assert result[0] is True
    assert enable_calls == [["enable-secret", "secret", "admin"], ["enable-secret", "secret", "admin"]]


def test_intelbras_olt_telnet_falls_back_to_running_config_devel(monkeypatch, tmp_path):
    seen_commands = []
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "open_pexpect_session",
        lambda *_args, **_kwargs: FakeChild(),
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "_open_and_login",
        lambda *_args, **_kwargs: "intelbras-olt>",
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "_enter_enable",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "_disable_pagination",
        lambda *_args, **_kwargs: None,
    )

    def fake_collect(_child, command, **_kwargs):
        seen_commands.append(command)
        if command == "show running-config-devel":
            return True, (
                "Starting configuration dump ...\n"
                "session timeout 10\n"
                "session command-wait on\n"
                "bridge-profile add ROUTER-PON-01 downlink vlan 2001 tagged router gtp 0\n"
            )
        return True, "%% Invalid command\n"

    monkeypatch.setattr(intelbras_olt_netmiko, "_send_collect", fake_collect)
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "close_pexpect_session",
        lambda _child: None,
    )
    monkeypatch.setattr(
        intelbras_olt_netmiko,
        "prepare_backup_path",
        lambda *_args, **_kwargs: str(tmp_path / "backup_devel.cfg"),
    )

    result = intelbras_olt_netmiko.realizar_backup(
        ip="10.0.0.4",
        usuario="admin",
        porta=23,
        nome_provedor="Tenant",
        nome_tipo_equip="OLT Intelbras",
        nome_dispositivo="Intelbras OLT Devel",
        parametros={"password": "secret", "use_telnet": True},
    )

    assert result[0] is True
    assert seen_commands[0] == "show running-config-devel"
    assert (tmp_path / "backup_devel.cfg").exists()


def test_backup_executor_supports_protocol_fallback_for_intelbras_olt():
    assert _supports_protocol_fallback("intelbras_olt_netmiko.py") is True

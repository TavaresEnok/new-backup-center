import importlib
import pathlib
import sys

from app.services.backup_executor import _supports_protocol_fallback


SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "scripts" / "backup_scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

datacom_olt_netmiko = importlib.import_module("datacom_olt_netmiko")


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
        return "paginate false\r\nOLT#"

    def send_command_timing(self, command, **_kwargs):
        return f"{command}\ninterface gpon 0/1\n onu add 1\n vlan 100\n" + ("x" * 120)


def test_datacom_olt_uses_ssh_when_use_telnet_is_false(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        datacom_olt_netmiko,
        "ConnectHandler",
        lambda **kwargs: FakeConnection(kwargs, calls),
    )
    monkeypatch.setattr(
        datacom_olt_netmiko,
        "prepare_backup_path",
        lambda *_args, **_kwargs: str(tmp_path / "backup.cfg"),
    )

    result = datacom_olt_netmiko.realizar_backup(
        ip="10.120.0.6",
        usuario="sgpconexaoolt",
        porta=22088,
        nome_provedor="Infotel",
        nome_tipo_equip="OLT Datacom",
        nome_dispositivo="INFOTEL - OLT DM - IPUEIRAS - IPUI",
        parametros={"password": "secret", "use_telnet": False},
    )

    assert result[0] is True
    assert len(calls) == 2
    assert all(call["device_type"] == "cisco_ios" for call in calls)
    assert (tmp_path / "backup.cfg").exists()


def test_datacom_olt_uses_telnet_when_requested(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        datacom_olt_netmiko,
        "ConnectHandler",
        lambda **kwargs: FakeConnection(kwargs, calls),
    )
    monkeypatch.setattr(
        datacom_olt_netmiko,
        "prepare_backup_path",
        lambda *_args, **_kwargs: str(tmp_path / "backup_telnet.cfg"),
    )

    result = datacom_olt_netmiko.realizar_backup(
        ip="10.10.10.10",
        usuario="user",
        porta=23,
        nome_provedor="Tenant",
        nome_tipo_equip="OLT Datacom",
        nome_dispositivo="OLT Datacom Telnet",
        parametros={"password": "secret", "use_telnet": True},
    )

    assert result[0] is True
    assert len(calls) == 2
    assert all(call["device_type"] == "cisco_ios_telnet" for call in calls)


def test_backup_executor_supports_protocol_fallback_for_datacom_olt():
    assert _supports_protocol_fallback("datacom_olt_netmiko.py") is True

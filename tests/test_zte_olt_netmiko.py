import importlib
import pathlib
import re
import sys

import pexpect


SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "scripts" / "backup_scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

zte_olt_netmiko = importlib.import_module("zte_olt_netmiko")


class FakeChild:
    pass


def test_zte_olt_accepts_compact_but_meaningful_config(monkeypatch, tmp_path):
    child = FakeChild()
    monkeypatch.setattr(
        zte_olt_netmiko,
        "open_pexpect_session",
        lambda *_args, **_kwargs: child,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "_login",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "_try_enable",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "close_pexpect_session",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "prepare_backup_path",
        lambda *_args, **_kwargs: str(tmp_path / "zte.cfg"),
    )

    seen = []

    def fake_collect(_child, command, **_kwargs):
        seen.append(command)
        if command == "show configuration":
            return True, (
                "show configuration\n"
                "interface gpon-olt_1/1/1\n"
                " vlan 110\n"
                " service-port 1 vport 1 user-vlan 110 vlan 110\n"
            )
        return True, "%% Invalid command\n"

    monkeypatch.setattr(zte_olt_netmiko, "_send_collect", fake_collect)

    result = zte_olt_netmiko.realizar_backup(
        ip="10.0.0.10",
        usuario="admin",
        porta=23,
        nome_provedor="Tenant",
        nome_tipo_equip="OLT ZTE",
        nome_dispositivo="ZTE Compact",
        parametros={"password": "secret", "use_telnet": True},
    )

    assert result[0] is True
    assert "show configuration" in seen
    assert (tmp_path / "zte.cfg").exists()


def test_zte_olt_accepts_infotel_running_config_shape(monkeypatch, tmp_path):
    child = FakeChild()
    monkeypatch.setattr(
        zte_olt_netmiko,
        "open_pexpect_session",
        lambda *_args, **_kwargs: child,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "_login",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "_try_enable",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "close_pexpect_session",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "prepare_backup_path",
        lambda *_args, **_kwargs: str(tmp_path / "zte-infotel.cfg"),
    )

    seen = []

    def fake_collect(_child, command, **_kwargs):
        seen.append(command)
        if command == "terminal length 0":
            return True, ""
        if command == "show running-config":
            return True, (
                "show running-config\n"
                "Building configuration...\n"
                "olleh\n"
                "timestamp_write: 19:18:56 05/08/2026\n"
                "config-version 2.1\n"
                "!\n"
                "crtv disable\n"
                "!\n"
                "load-balance enable\n"
                "!\n"
                "operator-mode NORMAL\n"
                "tacacs-server deadtime 5\n"
                "alarm enable\n"
                "end\n"
            )
        return True, "%% Invalid command\n"

    monkeypatch.setattr(zte_olt_netmiko, "_send_collect", fake_collect)

    result = zte_olt_netmiko.realizar_backup(
        ip="10.120.0.50",
        usuario="ajust",
        porta=23,
        nome_provedor="Infotel",
        nome_tipo_equip="OLT ZTE",
        nome_dispositivo="INFOTEL - OLT ZTE - LUZIMANGUES - LZMG",
        parametros={"password": "secret", "use_telnet": True},
    )

    assert result[0] is True
    assert "show running-config" in seen
    assert (tmp_path / "zte-infotel.cfg").exists()


def test_zte_colon_prompt_regex_ignores_timestamp_lines():
    assert re.search(
        zte_olt_netmiko.STANDALONE_COLON_PROMPT_RE,
        "Password:\n",
    )
    assert not re.search(
        zte_olt_netmiko.STANDALONE_COLON_PROMPT_RE,
        "timestamp_write: 19:18:56 05/08/2026\n",
    )


def test_zte_prompt_regex_does_not_treat_ok_brackets_as_prompt():
    assert re.search(zte_olt_netmiko.PROMPT_ANY_LINE, "A04-OLT#\n")
    assert re.search(zte_olt_netmiko.PROMPT_ANY_LINE, "<A04-OLT>\n")
    assert not re.search(zte_olt_netmiko.PROMPT_ANY_LINE, "[OK]\n")
    assert not re.search(zte_olt_netmiko.PROMPT_ANY_LINE, "[Done]\n")


def test_zte_send_collect_drains_stale_prompt_before_command():
    class FakeDrainChild:
        def __init__(self):
            self.sent = []
            self.before = ""
            self.after = ""
            self.drained = []

        def read_nonblocking(self, size=1, timeout=0):
            if not self.drained:
                self.drained.append("A04-OLT#")
                return "A04-OLT#"
            raise pexpect.TIMEOUT("no pending output")

        def sendline(self, command):
            self.sent.append(command)

        def expect(self, _patterns, timeout=0):
            self.before = (
                f"{self.sent[-1]}\n"
                "hostname A04-OLT-ZTE-C610-CURCURANA-LINEFIBRA\n"
                "vlan 100\n"
                "end\n"
            )
            self.after = "A04-OLT#"
            return 0

    child = FakeDrainChild()
    ok, output = zte_olt_netmiko._send_collect(child, "show running-config", timeout_seconds=10)

    assert ok is True
    assert child.drained == ["A04-OLT#"]
    assert child.sent == ["show running-config"]
    assert "A04-OLT#show running-config" not in output
    assert "hostname A04-OLT-ZTE-C610-CURCURANA-LINEFIBRA" in output


def test_zte_olt_still_rejects_short_invalid_output(monkeypatch, tmp_path):
    child = FakeChild()
    monkeypatch.setattr(
        zte_olt_netmiko,
        "open_pexpect_session",
        lambda *_args, **_kwargs: child,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "_login",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "_try_enable",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "close_pexpect_session",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "prepare_backup_path",
        lambda *_args, **_kwargs: str(tmp_path / "zte-invalid.cfg"),
    )
    monkeypatch.setattr(
        zte_olt_netmiko,
        "_send_collect",
        lambda *_args, **_kwargs: (True, "%% Invalid command\n"),
    )

    result = zte_olt_netmiko.realizar_backup(
        ip="10.0.0.11",
        usuario="admin",
        porta=23,
        nome_provedor="Tenant",
        nome_tipo_equip="OLT ZTE",
        nome_dispositivo="ZTE Invalid",
        parametros={"password": "secret", "use_telnet": True},
    )

    assert result[0] is False
    assert "Configuracao retornada muito curta/vazia." in result[1]

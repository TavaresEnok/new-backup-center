import importlib
import pathlib
import sys


SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "scripts" / "backup_scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

olt_cli_backup = importlib.import_module("olt_cli_backup")
parks_olt = importlib.import_module("parks_olt_netmiko")
maxprint_olt = importlib.import_module("maxprint_olt_netmiko")
tplink_olt = importlib.import_module("tplink_olt_netmiko")
cianet_olt = importlib.import_module("cianet_olt_netmiko")
switch_cisco = importlib.import_module("switch_cisco_netmiko")


class DummyChild:
    pass


def _patch_common(monkeypatch, tmp_path):
    monkeypatch.setattr(olt_cli_backup, "open_pexpect_session", lambda *_args, **_kwargs: DummyChild())
    monkeypatch.setattr(olt_cli_backup, "_login", lambda *_args, **_kwargs: (True, ""))
    monkeypatch.setattr(olt_cli_backup, "_try_enable", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(olt_cli_backup, "close_pexpect_session", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(olt_cli_backup, "prepare_backup_path", lambda *_args, **_kwargs: str(tmp_path / "olt.cfg"))


def test_olt_cli_helper_saves_meaningful_config(monkeypatch, tmp_path):
    _patch_common(monkeypatch, tmp_path)
    full_config = "\n".join(
        [
            "show running-config",
            "hostname OLT-PARKS",
            "vlan 100",
            "interface gpon 0/1",
            " onu 1 sn-auth ABCD1234",
            " service-port 1 vlan 100",
            *[f"interface gpon 0/{i}" for i in range(2, 24)],
            "end",
        ]
    )
    seen = []

    def fake_collect(_child, command, **_kwargs):
        seen.append(command)
        if command in parks_olt.PARKS_PROFILE.paging_commands:
            return True, ""
        if command == "show running-config":
            return True, full_config
        return True, "% Invalid input detected\n"

    monkeypatch.setattr(olt_cli_backup, "_send_collect", fake_collect)

    result = olt_cli_backup.run_olt_cli_backup(
        profile=parks_olt.PARKS_PROFILE,
        ip="10.0.0.1",
        usuario="admin",
        porta=23,
        nome_provedor="UltraNet",
        nome_tipo_equip="Olt Parks",
        nome_dispositivo="ULTRANET - OLT PARKS 1",
        parametros={"password": "secret", "use_telnet": True},
    )

    assert result[0] is True
    assert seen[0] in parks_olt.PARKS_PROFILE.paging_commands
    assert "show running-config" in seen
    assert "interface gpon 0/23" in (tmp_path / "olt.cfg").read_text(encoding="utf-8")


def test_olt_cli_helper_rejects_short_or_invalid_output(monkeypatch, tmp_path):
    _patch_common(monkeypatch, tmp_path)

    def fake_collect(_child, command, **_kwargs):
        if command in tplink_olt.TPLINK_PROFILE.paging_commands:
            return True, ""
        return True, "show running-config\n% Invalid input detected\nOLT#"

    monkeypatch.setattr(olt_cli_backup, "_send_collect", fake_collect)

    result = olt_cli_backup.run_olt_cli_backup(
        profile=tplink_olt.TPLINK_PROFILE,
        ip="10.0.0.1",
        usuario="admin",
        porta=23,
        nome_provedor="Pix Fibra",
        nome_tipo_equip="OLT TPLink",
        nome_dispositivo="PIX FIBRA - OLT TPLINK",
        parametros={"password": "secret", "use_telnet": True},
    )

    assert result[0] is False
    assert "curta/vazia" in result[1]
    assert not (tmp_path / "olt.cfg").exists()


def test_olt_cli_helper_rejects_incomplete_paged_output(monkeypatch, tmp_path):
    _patch_common(monkeypatch, tmp_path)
    partial_config = "\n".join(
        [
            "show saved-config",
            "#Saving user: autosave",
            "dba-profile profile-id 0 profile-name \"dba-profile_0\"",
            "ont-lineprofile gpon profile-id 400 profile-name \"lineprofile_400\"",
            "  --More ( Press 'Q' to quit )-- ",
        ]
    )

    def fake_collect(_child, command, **_kwargs):
        if command in maxprint_olt.MAXPRINT_PROFILE.paging_commands:
            return True, ""
        if command == "show saved-config":
            return False, partial_config
        return True, "Unknown command"

    monkeypatch.setattr(olt_cli_backup, "_send_collect", fake_collect)

    result = olt_cli_backup.run_olt_cli_backup(
        profile=maxprint_olt.MAXPRINT_PROFILE,
        ip="10.0.0.1",
        usuario="admin",
        porta=23,
        nome_provedor="SofiaNet",
        nome_tipo_equip="OLT Maxprint",
        nome_dispositivo="SOFIANET - OLT MAXPRINT",
        parametros={"password": "secret", "use_telnet": True},
    )

    assert result[0] is False
    assert "curta/vazia" in result[1]
    assert not (tmp_path / "olt.cfg").exists()


def test_olt_vendor_scripts_are_no_longer_generic_wrappers():
    for module, profile_name in (
        (parks_olt, "OLT Parks"),
        (maxprint_olt, "OLT Maxprint"),
        (tplink_olt, "OLT TPLink"),
        (cianet_olt, "OLT Cianet"),
    ):
        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        assert "run_profile_backup" not in source
        assert "olt_generic" not in source
        assert profile_name in source


def test_olt_prompt_regex_accepts_angle_and_plain_prompts():
    import re

    assert re.search(olt_cli_backup.PROMPT_ANY_LINE, "<OLT-TP-LINK>\n")
    assert re.search(olt_cli_backup.PROMPT_ANY_LINE, "PARKS_OLT#\n")
    assert re.search(olt_cli_backup.PROMPT_ANY_LINE, "MAXPRINT-OLT(config)#\n")
    assert re.search(olt_cli_backup.PROMPT_ANY_LINE, "(vtysh)\n")
    assert not re.search(olt_cli_backup.PROMPT_ANY_LINE, "[OK]\n")


def test_switch_cisco_config_validation_rejects_command_errors():
    good = (
        "show running-config\n"
        "version 15.2\n"
        "hostname SW-CORE\n"
        "interface Ethernet1/1\n"
        " switchport access vlan 100\n"
        "end\n"
    )
    bad = "show running-config\n% Invalid input detected at '^' marker.\nSW#"

    assert switch_cisco._looks_like_config(good)
    assert not switch_cisco._looks_like_config(bad)

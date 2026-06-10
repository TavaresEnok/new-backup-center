import importlib
import pathlib
import sys


SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "scripts" / "backup_scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

digistar_olt = importlib.import_module("digistar_olt_netmiko")


class DummyChild:
    pass


def _patch_common(monkeypatch, tmp_path):
    monkeypatch.setattr(digistar_olt, "open_pexpect_session", lambda *_args, **_kwargs: DummyChild())
    monkeypatch.setattr(digistar_olt, "_login", lambda *_args, **_kwargs: (True, ""))
    monkeypatch.setattr(digistar_olt, "_try_enable", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(digistar_olt, "close_pexpect_session", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(digistar_olt, "prepare_backup_path", lambda *_args, **_kwargs: str(tmp_path / "digistar.cfg"))


def test_digistar_prefers_running_config_with_space(monkeypatch, tmp_path):
    _patch_common(monkeypatch, tmp_path)
    full_config = "\n".join(
        [
            "show running config",
            "hostname OLT_ECOLIFE",
            "vlan 100",
            "interface gpon 0/1",
            " onu 1 sn-auth ABCD1234",
            " service-port 1 vlan 100",
            *[f"interface gpon 0/{i}" for i in range(2, 30)],
            "end",
        ]
    )
    seen = []

    def fake_collect(_child, command, **_kwargs):
        seen.append(command)
        if command in {"terminal length 0", "terminal len 0", "no paging", "screen-length 0", "set length 0"}:
            return True, ""
        if command == "show running config":
            return True, full_config
        return True, "% Error in '^' marker\nOLT_ECOLIFE>"

    monkeypatch.setattr(digistar_olt, "_send_collect", fake_collect)

    result = digistar_olt.realizar_backup(
        ip="10.0.0.1",
        usuario="admin",
        porta=22,
        nome_provedor="Rio Net",
        nome_tipo_equip="OLT Digistar",
        nome_dispositivo="RIONET - OLT DIGISTAR - BEACH CLASS",
        parametros={"password": "secret"},
    )

    assert result[0] is True
    assert seen.index("show running config") < seen.index("show running-config") if "show running-config" in seen else True
    content = (tmp_path / "digistar.cfg").read_text(encoding="utf-8")
    assert "hostname OLT_ECOLIFE" in content
    assert "interface gpon 0/29" in content


def test_digistar_rejects_old_hyphen_error_output(monkeypatch, tmp_path):
    _patch_common(monkeypatch, tmp_path)
    old_bad_output = "show running-config\n                 ^\n% Error in '^' marker\n\n\nOLT_ECOLIFE>"

    def fake_collect(_child, command, **_kwargs):
        if command in {"terminal length 0", "terminal len 0", "no paging", "screen-length 0", "set length 0"}:
            return True, ""
        return True, old_bad_output

    monkeypatch.setattr(digistar_olt, "_send_collect", fake_collect)

    result = digistar_olt.realizar_backup(
        ip="10.0.0.1",
        usuario="admin",
        porta=22,
        nome_provedor="Rio Net",
        nome_tipo_equip="OLT Digistar",
        nome_dispositivo="RIONET - OLT DIGISTAR - BEACH CLASS",
        parametros={"password": "secret"},
    )

    assert result[0] is False
    assert "curta/vazia" in result[1]
    assert not (tmp_path / "digistar.cfg").exists()


def test_digistar_prompt_accepts_underscore_hostname():
    import re

    assert re.search(digistar_olt.PROMPT_ANY_LINE, "OLT_ECOLIFE>\n")
    assert re.search(digistar_olt.PROMPT_ANY_LINE, "OLT_ECOLIFE#\n")

import importlib
import pathlib
import sys


SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "scripts" / "backup_scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

zte_olt = importlib.import_module("zte_olt_netmiko")


class DummyChild:
    pass


def _patch_common(monkeypatch, tmp_path):
    monkeypatch.setattr(zte_olt, "open_pexpect_session", lambda *_args, **_kwargs: DummyChild())
    monkeypatch.setattr(zte_olt, "_login", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(zte_olt, "_try_enable", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(zte_olt, "close_pexpect_session", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(zte_olt, "prepare_backup_path", lambda *_args, **_kwargs: str(tmp_path / "zte.cfg"))


def test_zte_olt_rejects_hostname_login_only_partial(monkeypatch, tmp_path):
    _patch_common(monkeypatch, tmp_path)
    partial = "hostname A04-OLT-ZTE-C610-CURCURANA-LINEFIBRA\nlogin authentication"

    def fake_collect(_child, command, **_kwargs):
        if command in {"terminal length 0", "screen-length 0 temporary", "no page"}:
            return True, ""
        return True, partial

    monkeypatch.setattr(zte_olt, "_send_collect", fake_collect)

    result = zte_olt.realizar_backup(
        ip="10.0.0.1",
        usuario="admin",
        porta=22,
        nome_provedor="Pix Fibra",
        nome_tipo_equip="OLT ZTE",
        nome_dispositivo="PIX FIBRA - OLT ZTE - CURCURANA-LINEFIBRA",
        parametros={"password": "secret"},
    )

    assert result[0] is False
    assert "curta/vazia" in result[1]
    assert not (tmp_path / "zte.cfg").exists()


def test_zte_olt_accepts_realistic_running_config(monkeypatch, tmp_path):
    _patch_common(monkeypatch, tmp_path)
    full_config = "\n".join(
        [
            "hostname A04-OLT-ZTE-C610-CURCURANA-LINEFIBRA",
            "vlan 100",
            "interface gpon-olt_1/1/1",
            " onu 1 type ZTE-F660 sn ZTEGC1234567",
            "interface vport-1/1/1.1:1",
            " service-port 1 vport 1 user-vlan 100 vlan 100",
            "pon-onu-mng gpon-onu_1/1/1:1",
            *[f" service-port {i} vport {i} user-vlan 100 vlan 100" for i in range(2, 40)],
            "end",
        ]
    )

    def fake_collect(_child, command, **_kwargs):
        if command in {"terminal length 0", "screen-length 0 temporary", "no page"}:
            return True, ""
        if command == "show running-config":
            return True, full_config
        return True, "unknown command"

    monkeypatch.setattr(zte_olt, "_send_collect", fake_collect)

    result = zte_olt.realizar_backup(
        ip="10.0.0.1",
        usuario="admin",
        porta=22,
        nome_provedor="Pix Fibra",
        nome_tipo_equip="OLT ZTE",
        nome_dispositivo="PIX FIBRA - OLT ZTE - CURCURANA-LINEFIBRA",
        parametros={"password": "secret"},
    )

    assert result[0] is True
    content = (tmp_path / "zte.cfg").read_text(encoding="utf-8")
    assert "interface gpon-olt_1/1/1" in content
    assert "service-port 39" in content

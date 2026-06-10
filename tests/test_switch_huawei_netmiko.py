import importlib
import pathlib
import sys


SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "scripts" / "backup_scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

switch_huawei = importlib.import_module("switch_huawei_netmiko")


def test_switch_huawei_detects_legacy_ssh_algorithm_error():
    detail = (
        "huawei: NetmikoTimeoutException: A paramiko SSHException occurred during "
        "connection creation: Incompatible ssh peer (no acceptable kex algorithm)"
    )

    assert switch_huawei._is_ssh_algorithm_error(detail) is True


def test_switch_huawei_legacy_ssh_command_enables_old_algorithms():
    command = switch_huawei._ssh_legacy_command("192.0.2.10", "admin", 2222)

    assert "KexAlgorithms=+diffie-hellman-group1-sha1" in command
    assert "HostKeyAlgorithms=+ssh-rsa,ssh-dss" in command
    assert "admin@192.0.2.10 -p 2222" in command


def test_switch_huawei_falls_back_to_legacy_ssh_on_kex_error(monkeypatch, tmp_path):
    def fake_connect_handler(**_kwargs):
        raise RuntimeError(
            "A paramiko SSHException occurred during connection creation: "
            "Incompatible ssh peer (no acceptable kex algorithm)"
        )

    legacy_calls = []

    def fake_legacy_backup(**kwargs):
        legacy_calls.append(kwargs)
        backup_path = kwargs["backup_path"]
        pathlib.Path(backup_path).write_text("sysname SW-HW\ninterface XGigabitEthernet0/0/1\nreturn\n", encoding="utf-8")
        return (True, "Backup do Switch Huawei concluido com sucesso (SSH legado).", backup_path)

    monkeypatch.setattr(switch_huawei, "ConnectHandler", fake_connect_handler)
    monkeypatch.setattr(switch_huawei, "_legacy_ssh_backup", fake_legacy_backup)
    monkeypatch.setattr(
        switch_huawei,
        "prepare_backup_path",
        lambda *_args, **_kwargs: str(tmp_path / "switch.cfg"),
    )

    result = switch_huawei.realizar_backup(
        ip="192.0.2.10",
        usuario="admin",
        porta=22,
        nome_provedor="GL Solucoes",
        nome_tipo_equip="Switch Huawei",
        nome_dispositivo="SW-HW",
        parametros={"password": "secret"},
    )

    assert result[0] is True
    assert legacy_calls
    assert legacy_calls[0]["ip"] == "192.0.2.10"


def test_switch_huawei_does_not_use_legacy_ssh_for_auth_error(monkeypatch):
    def fake_connect_handler(**_kwargs):
        raise RuntimeError("Authentication failed")

    monkeypatch.setattr(switch_huawei, "ConnectHandler", fake_connect_handler)

    def fail_if_called(**_kwargs):
        raise AssertionError("legacy fallback should not run for authentication errors")

    monkeypatch.setattr(switch_huawei, "_legacy_ssh_backup", fail_if_called)

    result = switch_huawei.realizar_backup(
        ip="192.0.2.10",
        usuario="admin",
        porta=22,
        nome_provedor="GL Solucoes",
        nome_tipo_equip="Switch Huawei",
        nome_dispositivo="SW-HW",
        parametros={"password": "secret"},
    )

    assert result[0] is False
    assert result[3] == "AUTENTICACAO"

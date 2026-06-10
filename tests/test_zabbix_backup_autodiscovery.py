import importlib.util
import os
import sys
import tempfile
from pathlib import Path


SCRIPT_FILE = Path("/srv/backup_center_new/app/scripts/backup_scripts/Zabbix_backup.py")
SCRIPT_DIR = str(SCRIPT_FILE.parent)


def _load_script_module(module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, str(SCRIPT_FILE))
    module = importlib.util.module_from_spec(spec)
    if SCRIPT_DIR not in sys.path:
        sys.path.insert(0, SCRIPT_DIR)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _build_fakes(commands, dump_output=""):
    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def is_alive(self):
            return True

        def send_command_timing(self, cmd, **kwargs):
            commands.append(str(cmd))
            if str(cmd).strip() == "whoami":
                return "root\n#"
            if "grep -E '^(DB(Name|User|Password))='" in str(cmd):
                return dump_output
            if "pg_dump" in str(cmd) or "mysqldump" in str(cmd):
                return "__BC_DUMP_STATUS__ dump=0 gzip=0 size=256\n"
            return ""

    class FakeConnectHandler:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return FakeConn()

        def __exit__(self, exc_type, exc, tb):
            return False

    class FakeSFTP:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, remote, local):
            os.makedirs(os.path.dirname(local), exist_ok=True)
            with open(local, "wb") as handle:
                handle.write(b"x" * 256)

    class FakeSSHClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def set_missing_host_key_policy(self, _policy):
            pass

        def connect(self, **kwargs):
            pass

        def open_sftp(self):
            return FakeSFTP()

    return FakeConnectHandler, FakeSSHClient


def test_zabbix_backup_uses_manual_db_params_without_conf_lookup(monkeypatch):
    mod = _load_script_module("zabbix_backup_manual")
    commands = []
    fake_ch, fake_ssh = _build_fakes(commands, dump_output="")
    base_tmp = tempfile.mkdtemp(prefix="zbx-manual-")

    monkeypatch.setattr(mod, "ConnectHandler", fake_ch)
    monkeypatch.setattr(mod.paramiko, "SSHClient", fake_ssh)
    monkeypatch.setattr(
        mod,
        "prepare_backup_path",
        lambda *a, **k: os.path.join(base_tmp, "backup.sql.gz"),
    )

    result = mod.realizar_backup(
        ip="10.0.0.10",
        usuario="admin",
        porta=22,
        nome_provedor="P",
        nome_tipo_equip="T",
        nome_dispositivo="ZBX",
        backup_base_path=base_tmp,
        parametros={
            "password": "ssh-pass",
            "db_type": "postgres",
            "db_name": "zabbix",
            "db_user": "ajust",
            "db_password": "abc123",
        },
    )

    assert result[0] is True
    assert any("pg_dump" in cmd for cmd in commands)
    assert not any("zabbix_server.conf" in cmd for cmd in commands)


def test_zabbix_backup_autodiscovers_db_params_from_conf(monkeypatch):
    mod = _load_script_module("zabbix_backup_autodetect")
    commands = []
    conf_output = "\n".join(
        [
            "DBName=zabbix",
            "DBUser=ajust",
            "DBPassword=3FguQbbP12Aj",
        ]
    )
    fake_ch, fake_ssh = _build_fakes(commands, dump_output=conf_output)
    base_tmp = tempfile.mkdtemp(prefix="zbx-auto-")

    monkeypatch.setattr(mod, "ConnectHandler", fake_ch)
    monkeypatch.setattr(mod.paramiko, "SSHClient", fake_ssh)
    monkeypatch.setattr(
        mod,
        "prepare_backup_path",
        lambda *a, **k: os.path.join(base_tmp, "backup.sql.gz"),
    )

    result = mod.realizar_backup(
        ip="10.0.0.11",
        usuario="admin",
        porta=22,
        nome_provedor="P",
        nome_tipo_equip="T",
        nome_dispositivo="ZBX",
        backup_base_path=base_tmp,
        parametros={
            "password": "ssh-pass",
            "db_type": "postgres",
        },
    )

    assert result[0] is True
    assert any("zabbix_server.conf" in cmd for cmd in commands)
    dump_cmds = [cmd for cmd in commands if "pg_dump" in cmd]
    assert dump_cmds
    assert "PGPASSWORD=3FguQbbP12Aj" in dump_cmds[0]
    assert "pg_dump -h localhost -U ajust" in dump_cmds[0]


def test_zabbix_backup_fails_when_db_params_missing_and_conf_empty(monkeypatch):
    mod = _load_script_module("zabbix_backup_missing")
    commands = []
    fake_ch, fake_ssh = _build_fakes(commands, dump_output="")
    base_tmp = tempfile.mkdtemp(prefix="zbx-missing-")

    monkeypatch.setattr(mod, "ConnectHandler", fake_ch)
    monkeypatch.setattr(mod.paramiko, "SSHClient", fake_ssh)
    monkeypatch.setattr(
        mod,
        "prepare_backup_path",
        lambda *a, **k: os.path.join(base_tmp, "backup.sql.gz"),
    )

    result = mod.realizar_backup(
        ip="10.0.0.12",
        usuario="admin",
        porta=22,
        nome_provedor="P",
        nome_tipo_equip="T",
        nome_dispositivo="ZBX",
        backup_base_path=base_tmp,
        parametros={
            "password": "ssh-pass",
            "db_type": "postgres",
        },
    )

    assert result[0] is False
    assert result[3] == "CONFIGURACAO"
    assert any("zabbix_server.conf" in cmd for cmd in commands)


def test_zabbix_backup_rejects_invalid_db_type(monkeypatch):
    mod = _load_script_module("zabbix_backup_invalid_type")
    commands = []
    fake_ch, fake_ssh = _build_fakes(commands, dump_output="")
    base_tmp = tempfile.mkdtemp(prefix="zbx-invalid-")

    monkeypatch.setattr(mod, "ConnectHandler", fake_ch)
    monkeypatch.setattr(mod.paramiko, "SSHClient", fake_ssh)
    monkeypatch.setattr(
        mod,
        "prepare_backup_path",
        lambda *a, **k: os.path.join(base_tmp, "backup.sql.gz"),
    )

    result = mod.realizar_backup(
        ip="10.0.0.13",
        usuario="admin",
        porta=22,
        nome_provedor="P",
        nome_tipo_equip="T",
        nome_dispositivo="ZBX",
        parametros={
            "password": "ssh-pass",
            "db_type": "oracle",
            "db_name": "zabbix",
            "db_user": "u",
            "db_password": "p",
        },
    )
    assert result[0] is False
    assert result[3] == "CONFIGURACAO"


def test_zabbix_dump_result_parser_extracts_status_and_error():
    mod = _load_script_module("zabbix_backup_dump_parser")

    result = mod._parse_dump_result(
        "__BC_DUMP_STATUS__ dump=1 gzip=0 size=20\n__BC_DUMP_ERROR__\npg_dump: command not found\n"
    )

    assert result["dump_status"] == 1
    assert result["gzip_status"] == 0
    assert result["size"] == 20
    assert "pg_dump" in result["error"]


def test_zabbix_friendly_dump_error_for_missing_postgres_client():
    mod = _load_script_module("zabbix_backup_dump_error_pg")

    category, detail = mod._friendly_dump_error("bash: pg_dump: command not found", "postgres")

    assert category == "CONFIGURACAO"
    assert "PostgreSQL" in detail
    assert "pg_dump" in detail


def test_zabbix_friendly_dump_error_for_mariadb_auth():
    mod = _load_script_module("zabbix_backup_dump_error_mysql")

    category, detail = mod._friendly_dump_error("mysqldump: Got error: 1045: Access denied", "mariadb")

    assert category == "AUTENTICACAO"
    assert "Credenciais" in detail
    assert "MariaDB" in detail

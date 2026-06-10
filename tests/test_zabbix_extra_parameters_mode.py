from types import SimpleNamespace

from app.web.tenant.devices import (
    _collect_device_extra_parameters,
    ZABBIX_AUTODISCOVERY_MODE_AUTOMATIC,
    ZABBIX_DEFAULT_EXCLUDE_TABLES,
)


class _FakeForm(dict):
    def get(self, key, default=None):
        return super().get(key, default)


def _zabbix_type():
    return SimpleNamespace(
        script_name="Zabbix_backup.py",
        required_parameters="db_type\ndb_name\ndb_user\ndb_password\nexclude_tables",
    )


def test_zabbix_automatic_mode_preserves_existing_db_credentials():
    device_type = _zabbix_type()
    existing = {
        "db_type": "postgres",
        "db_name": "zabbix_prod",
        "db_user": "zabbix_user",
        "db_password": "super-secret",
        "exclude_tables": "history,trends",
    }
    form = _FakeForm(
        {
            "extra__db_credentials_mode": "automatic",
            "extra__db_type": "",
            "extra__db_name": "",
            "extra__db_user": "",
            "extra__db_password": "",
            "extra__exclude_tables": "",
        }
    )

    result = _collect_device_extra_parameters(form, device_type, existing_extra=existing)

    assert result["db_credentials_mode"] == ZABBIX_AUTODISCOVERY_MODE_AUTOMATIC
    assert result["db_name"] == "zabbix_prod"
    assert result["db_user"] == "zabbix_user"
    assert result["db_password"] == "super-secret"
    assert result["exclude_tables"] == ZABBIX_DEFAULT_EXCLUDE_TABLES
    assert result["db_type"] == "postgres"


def test_zabbix_manual_mode_allows_db_updates():
    device_type = _zabbix_type()
    existing = {
        "db_type": "postgres",
        "db_name": "old_name",
        "db_user": "old_user",
        "db_password": "old_pass",
    }
    form = _FakeForm(
        {
            "extra__db_credentials_mode": "manual",
            "extra__db_type": "mysql",
            "extra__db_name": "new_name",
            "extra__db_user": "new_user",
            "extra__db_password": "new_pass",
            "extra__exclude_tables": "history_uint,trends_uint",
        }
    )

    result = _collect_device_extra_parameters(form, device_type, existing_extra=existing)

    assert result["db_credentials_mode"] == "manual"
    assert result["db_type"] == "mariadb"
    assert result["db_name"] == "new_name"
    assert result["db_user"] == "new_user"
    assert result["db_password"] == "new_pass"
    assert result["exclude_tables"] == "history_uint,trends_uint"


def test_zabbix_automatic_mode_new_device_keeps_db_fields_empty_for_runtime_discovery():
    device_type = _zabbix_type()
    form = _FakeForm(
        {
            "extra__db_credentials_mode": "automatic",
            "extra__db_type": "",
            "extra__db_name": "",
            "extra__db_user": "",
            "extra__db_password": "",
            "extra__exclude_tables": "",
        }
    )

    result = _collect_device_extra_parameters(form, device_type, existing_extra={})

    assert result["db_credentials_mode"] == ZABBIX_AUTODISCOVERY_MODE_AUTOMATIC
    assert result["db_type"] == "postgres"
    assert result["exclude_tables"] == ZABBIX_DEFAULT_EXCLUDE_TABLES
    assert "db_name" not in result
    assert "db_user" not in result
    assert "db_password" not in result

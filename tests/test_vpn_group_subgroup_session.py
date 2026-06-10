import uuid
from contextlib import contextmanager
from types import SimpleNamespace

from app.core.database import SessionLocal
from app.core.security import encrypt_password
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.device_subgroup import DeviceSubgroup
from app.models.tenant import Tenant
from app.services.vpn_service import VpnError, VpnService
from app.tasks.backups import run_vpn_group_backups_task


def test_vpn_group_task_keeps_subgroup_available_after_db_close(monkeypatch):
    tenant_id = uuid.uuid4()
    group_id = uuid.uuid4()
    subgroup_id = uuid.uuid4()
    device_id = uuid.uuid4()

    db = SessionLocal()
    try:
        tenant = Tenant(
            id=tenant_id,
            slug=f"tenant-vpn-subgroup-{uuid.uuid4().hex[:8]}",
            name="Tenant VPN Subgrupo",
            email="tenant-vpn-subgroup@test.local",
            is_active=True,
        )
        group = DeviceGroup(
            id=group_id,
            tenant_id=tenant_id,
            name="Grupo Direto",
            slug=f"grupo-direto-{uuid.uuid4().hex[:8]}",
            connection_type="direct",
            uses_vpn=False,
            vpn_server="vpn.test.local",
            vpn_username="vpn-user",
            vpn_password_encrypted=encrypt_password("vpn-pass"),
            is_active=True,
        )
        subgroup = DeviceSubgroup(
            id=subgroup_id,
            tenant_id=tenant_id,
            group_id=group_id,
            name="Subgrupo VPN",
            connection_type="vpn",
            is_active=True,
        )
        device = Device(
            id=device_id,
            tenant_id=tenant_id,
            group_id=group_id,
            subgroup_id=subgroup_id,
            name="Device VPN via Subgrupo",
            ip_address="10.20.30.40",
            port=22,
            username="admin",
            password_encrypted=encrypt_password("secret"),
            backup_scheduled=True,
            is_active=True,
        )
        db.add_all([tenant, group, subgroup, device])
        db.commit()
    finally:
        db.close()

    @contextmanager
    def _noop_vpn_session(*_args, **_kwargs):
        yield

    calls = []

    monkeypatch.setattr("app.tasks.backups._should_stop_now", lambda *_args, **_kwargs: False)
    monkeypatch.setattr("app.services.vpn_service.vpn_service.ensure_worker_ready", lambda: None)
    monkeypatch.setattr("app.services.vpn_service.vpn_service.vpn_session", _noop_vpn_session)
    monkeypatch.setattr("app.services.realtime_backup_logs.update_task_meta", lambda *a, **k: None)
    monkeypatch.setattr("app.services.realtime_backup_logs.append_task_log", lambda *a, **k: None)
    monkeypatch.setattr(
        "app.services.backup_executor.backup_executor.run_backup_for_device_id",
        lambda device_id_arg, **_kwargs: (calls.append(str(device_id_arg)) or True, "ok"),
    )

    result = run_vpn_group_backups_task.run(str(group_id), str(tenant_id), [str(device_id)])

    assert result["success"] == 1
    assert result["failed"] == 0
    assert calls == [str(device_id)]


def test_vpn_activation_unknown_reason_retries_with_eth0(monkeypatch):
    service = VpnService()
    calls = []

    monkeypatch.setattr("app.services.vpn_service.shutil.which", lambda _cmd: "/usr/bin/nmcli")
    monkeypatch.setattr("app.services.vpn_service.decrypt_password", lambda value: value)

    def fake_run_nmcli(args, timeout=60, check=True):
        calls.append(tuple(args))
        if args[:4] == ["--terse", "--fields", "RUNNING", "general"]:
            return SimpleNamespace(returncode=0, stdout="running\n", stderr="")
        if args[:5] == ["--terse", "--fields", "NAME,TYPE,STATE", "con", "show"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[:5] == ["--terse", "--fields", "NAME,TYPE", "con", "show"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[:2] == ["device", "status"]:
            return SimpleNamespace(returncode=0, stdout="eth0 ethernet connected\n", stderr="")
        if args == ["connection", "up", "group_vpn_111111111111"]:
            raise VpnError(
                "nmcli connection up group_vpn_111111111111 falhou: "
                "Error: Connection activation failed: Unknown reason "
                "Hint: use 'journalctl -xe NM_CONNECTION=abc + NM_DEVICE=eth0'"
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(service, "_run_nmcli", fake_run_nmcli)

    group = SimpleNamespace(
        id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        name="Grupo VPN",
        uses_vpn=True,
        vpn_server="vpn.test.local",
        vpn_username="vpn-user",
        vpn_password_encrypted="vpn-pass",
        vpn_ipsec_secret_encrypted=None,
    )

    assert service.connect_group_vpn(group) == "group_vpn_111111111111"
    assert ("connection", "up", "container-eth0") in calls
    assert ("connection", "up", "group_vpn_111111111111", "ifname", "eth0") in calls


def test_isolated_vpn_session_uses_group_lock_not_global_lock(monkeypatch, tmp_path):
    service = VpnService()
    service.GROUP_LOCK_DIR = str(tmp_path)
    service.CONNECT_RETRIES = 1

    group_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    group = SimpleNamespace(id=group_id, name="Grupo VPN", uses_vpn=True)
    events = []

    monkeypatch.setenv("VPN_ISOLATED_WORKER", "1")
    monkeypatch.setattr(
        service,
        "acquire_lock",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("global lock should not be used")),
    )
    monkeypatch.setattr(service, "connect_group_vpn", lambda *_args, **_kwargs: events.append("connect"))
    monkeypatch.setattr(service, "disconnect_group_vpn", lambda *_args, **_kwargs: events.append("disconnect"))

    with service.vpn_session(group):
        events.append("inside")

    assert events == ["connect", "inside", "disconnect"]
    assert (tmp_path / f"{group_id}.lock").exists()

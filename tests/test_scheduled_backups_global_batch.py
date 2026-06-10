import uuid
from datetime import datetime, timedelta

from app.core.database import SessionLocal
from app.core.security import encrypt_password
from app.models.device import Device
from app.models.schedule import Schedule, ScheduleFrequency
from app.models.tenant import Tenant
from app.tasks.backups import run_backup_task, run_scheduled_backups, run_vpn_group_backups_task


def test_run_scheduled_backups_queues_full_tenant_batch(monkeypatch):
    queued_direct = []
    queued_vpn = []

    monkeypatch.setattr(run_backup_task, "delay", lambda device_id: queued_direct.append(str(device_id)))
    monkeypatch.setattr(
        run_vpn_group_backups_task,
        "apply_async",
        lambda *args, **kwargs: queued_vpn.append((args, kwargs)),
    )

    tenant_id = uuid.uuid4()
    db = SessionLocal()
    try:
        tenant = Tenant(
            id=tenant_id,
            slug=f"tenant-scheduled-batch-{uuid.uuid4().hex[:8]}",
            name="Tenant Agendamento Global",
            email="tenant-scheduled-batch@test.local",
            is_active=True,
        )
        device_due = Device(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            name="Device Due",
            ip_address="10.10.10.1",
            port=22,
            username="admin",
            password_encrypted=encrypt_password("secret"),
            backup_scheduled=True,
            is_active=True,
        )
        device_not_due = Device(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            name="Device Not Due",
            ip_address="10.10.10.2",
            port=22,
            username="admin",
            password_encrypted=encrypt_password("secret"),
            backup_scheduled=True,
            is_active=True,
        )
        now = datetime.utcnow()
        schedule_due = Schedule(
            id=uuid.uuid4(),
            device_id=device_due.id,
            frequency=ScheduleFrequency.DAILY,
            time="03:00",
            is_active=True,
            next_run_at=now - timedelta(minutes=5),
        )
        schedule_not_due = Schedule(
            id=uuid.uuid4(),
            device_id=device_not_due.id,
            frequency=ScheduleFrequency.DAILY,
            time="05:00",
            is_active=True,
            next_run_at=now + timedelta(hours=2),
        )
        db.add_all([tenant, device_due, device_not_due, schedule_due, schedule_not_due])
        db.commit()

        result = run_scheduled_backups()

        assert result["tenant_batches_queued"] == 1
        assert result["devices_queued"] == 2
        assert set(queued_direct) == {str(device_due.id), str(device_not_due.id)}
        assert queued_vpn == []

        db.refresh(schedule_due)
        db.refresh(schedule_not_due)
        assert schedule_due.last_run_at is not None
        assert schedule_not_due.last_run_at is not None
        assert schedule_due.next_run_at > now
        assert schedule_not_due.next_run_at > now
        assert schedule_due.frequency == ScheduleFrequency.DAILY
        assert schedule_not_due.frequency == ScheduleFrequency.DAILY
        assert schedule_due.day_of_week is None
        assert schedule_due.day_of_month is None
        assert schedule_not_due.day_of_week is None
        assert schedule_not_due.day_of_month is None
        assert schedule_due.time == "03:00"
        assert schedule_not_due.time == "03:00"
    finally:
        db.close()

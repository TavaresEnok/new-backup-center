from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "backup_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

from app.services.backup_service import BackupService
from app.services.device_service import DeviceService
from app.models.backup import Backup, BackupStatus
from app.core.database import SessionLocal
import datetime
import logging

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, max_retries=3)
def backup_device_task(self, device_id: str):
    db = SessionLocal()
    try:
        from app.models.device import Device
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return f"Device {device_id} not found"

        # Create Backup record
        backup_record = Backup(
            device_id=device.id,
            status=BackupStatus.IN_PROGRESS,
            started_at=datetime.datetime.utcnow()
        )
        db.add(backup_record)
        db.commit()

        try:
            # Execute SSH Backup
            config_data = BackupService.execute_backup(device)
            
            # Save to file
            file_path = BackupService.save_backup_file(
                str(device.tenant_id), str(device.id), config_data
            )
            
            # Update success
            backup_record.status = BackupStatus.SUCCESS
            backup_record.file_path = file_path
            backup_record.file_size_bytes = len(config_data)
            backup_record.completed_at = datetime.datetime.utcnow()
            backup_record.duration_seconds = (backup_record.completed_at - backup_record.started_at).seconds
            
            device.last_backup_at = datetime.datetime.utcnow()
            device.last_connection_status = 'online'
            
        except Exception as e:
            backup_record.status = BackupStatus.FAILED
            backup_record.error_message = str(e)
            backup_record.completed_at = datetime.datetime.utcnow()
            device.last_connection_status = 'error'
            raise e # Retry will be handled by celery decorator

        db.commit()
        return f"Backup {backup_record.id} success"

    except Exception as e:
        db.rollback()
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e, countdown=60)
        return f"Backup failed: {str(e)}"
    finally:
        db.close()

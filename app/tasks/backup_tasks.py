"""Compatibility guard for the old backup Celery task.

The active backup pipeline lives in app.tasks.backups and is wired through
app.celery_app. Keeping this module as a disabled wrapper prevents accidental
use of the legacy path, which did not enforce the current queue, Jump Host
slot, circuit-breaker and observability controls.
"""

import logging

from app.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="app.tasks.backup_tasks.backup_device_task")
def backup_device_task(self, device_id: str):
    message = (
        "backup_device_task legado desativado. Use app.tasks.backups.run_backup_task "
        "para executar backups com filas, locks e limites atuais."
    )
    logger.error("%s device_id=%s task_id=%s", message, device_id, getattr(self.request, "id", None))
    raise RuntimeError(message)

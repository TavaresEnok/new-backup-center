"""
ConfiguraÃ§Ã£o do Celery para processamento assÃ­ncrono de tarefas.

Para iniciar o worker Celery:
    celery -A app.celery_app worker --loglevel=info

Para iniciar o beat scheduler (tarefas periÃ³dicas):
    celery -A app.celery_app beat --loglevel=info
"""

from celery import Celery
from celery.signals import worker_process_init, worker_process_shutdown
from celery.schedules import crontab
from kombu import Queue
import os
from datetime import timedelta
from app.core.logging_config import setup_logging
from app.services.billing_policy_service import BillingPolicyService
from app.services.device_subgroup_service import DeviceSubgroupService

setup_logging()
BillingPolicyService.ensure_schema()
DeviceSubgroupService.ensure_schema()

# ConfiguraÃ§Ã£o do broker (Redis)
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
APP_TIMEZONE = os.environ.get('APP_TIMEZONE', 'America/Recife')

# Por padrao nao aplica hard time limit global.
# Alguns backups (especialmente grupos VPN) podem ultrapassar 5 minutos.
_task_time_limit_env = str(os.environ.get('CELERY_TASK_TIME_LIMIT', '')).strip()
_task_soft_time_limit_env = str(os.environ.get('CELERY_TASK_SOFT_TIME_LIMIT', '')).strip()
_result_expires_env = str(os.environ.get('CELERY_RESULT_EXPIRES_SECONDS', '86400')).strip()

TASK_TIME_LIMIT = int(_task_time_limit_env) if _task_time_limit_env.isdigit() else None
TASK_SOFT_TIME_LIMIT = int(_task_soft_time_limit_env) if _task_soft_time_limit_env.isdigit() else None
RESULT_EXPIRES = int(_result_expires_env) if _result_expires_env.isdigit() else 86400


def _env_int(name: str, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    raw = str(os.environ.get(name, default)).strip()
    try:
        value = int(raw)
    except Exception:
        value = int(default)
    if value < minimum:
        value = minimum
    if maximum is not None and value > maximum:
        value = maximum
    return value


SCHEDULED_BACKUPS_INTERVAL_SECONDS = _env_int(
    "CELERY_BEAT_SCHEDULED_BACKUPS_SECONDS",
    60,
    minimum=30,
    maximum=3600,
)
# Cria instÃ¢ncia do Celery
celery_app = Celery(
    'backup_center',
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=['app.tasks.monitoring', 'app.tasks.reports', 'app.tasks.backups', 'app.tasks.billing']
)

# ConfiguraÃ§Ãµes
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone=APP_TIMEZONE,
    enable_utc=True,
    task_track_started=True,
    task_time_limit=TASK_TIME_LIMIT,
    task_soft_time_limit=TASK_SOFT_TIME_LIMIT,
    worker_prefetch_multiplier=1,
    result_expires=RESULT_EXPIRES,
    task_default_queue='celery',
    task_queues=(
        Queue('celery'),
        Queue('jump_queue'),
        Queue('vpn_queue'),
    ),
    task_routes={
        'app.tasks.backups.run_vpn_group_backups_task': {'queue': 'vpn_queue'},
    },
)


@worker_process_init.connect
def _dispose_db_pool_on_fork(**_kwargs):
    """
    Evita reuso de conexoes herdadas no prefork do Celery.
    Isso reduz erros intermitentes de libpq/SQLAlchemy sob carga.
    """
    try:
        from app.core.database import engine
        engine.dispose(close=False)
    except Exception:
        pass


@worker_process_shutdown.connect
def _dispose_db_pool_on_worker_shutdown(**_kwargs):
    try:
        from app.core.database import engine
        engine.dispose()
    except Exception:
        pass

# Tarefas periÃ³dicas (Celery Beat)
celery_app.conf.beat_schedule = {
    # Executa a varredura da janela global diaria por tenant.
    'run-scheduled-backups-periodic': {
        'task': 'app.tasks.backups.run_scheduled_backups',
        'schedule': timedelta(seconds=SCHEDULED_BACKUPS_INTERVAL_SECONDS),
    },
    # Enviar relatÃ³rios diÃ¡rios Ã s 8h
    'send-daily-reports': {
        'task': 'app.tasks.reports.send_scheduled_reports',
        'schedule': crontab(hour=8, minute=0),
        'args': ('daily',)
    },
    # Enviar relatÃ³rios semanais Ã s segundas-feiras Ã s 9h
    'send-weekly-reports': {
        'task': 'app.tasks.reports.send_scheduled_reports',
        'schedule': crontab(hour=9, minute=0, day_of_week='monday'),
        'args': ('weekly',)
    },
    # Limpeza de backups expirados (diariamente 04:30, fora da janela de backups automaticos)
    'purge-expired-backups': {
        'task': 'app.tasks.backups.purge_expired_backups',
        'schedule': crontab(hour=4, minute=30),
    },
    # Limpeza automatica de backups com falha (seg e qui as 06:00, fora da janela de backups)
    'purge-failed-backups-every-3-days': {
        'task': 'app.tasks.backups.purge_failed_backups_periodic',
        'schedule': crontab(hour=6, minute=0, day_of_week='monday,thursday'),
    },
    # Limpeza automatica de logs de atividade (diariamente 05:00, fora da janela de backups automaticos)
    'purge-activity-logs-daily': {
        'task': 'app.tasks.backups.purge_activity_logs_periodic',
        'schedule': crontab(hour=5, minute=0),
    },
    # Politica de cobranca/acesso (a cada hora)
    'enforce-tenant-billing-access-hourly': {
        'task': 'app.tasks.billing.enforce_tenant_billing_access',
        'schedule': crontab(minute=0),
    },
}


# FunÃ§Ã£o para obter contexto Flask dentro das tasks
def get_flask_app():
    """Retorna a aplicaÃ§Ã£o Flask para uso dentro das tasks Celery."""
    from app import create_flask_app
    return create_flask_app()

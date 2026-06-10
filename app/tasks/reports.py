"""
Tasks Celery para geração e envio de relatórios.
"""

from app.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.tenant import Tenant
from app.models.report import Report, ReportSchedule
from app.services.report_service import ReportService
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def generate_report_task(self, report_id: str):
    """
    Task para gerar um relatório específico.
    
    Args:
        report_id: UUID do relatório a ser gerado
    """
    db = SessionLocal()
    
    try:
        report = ReportService.get_report(db, report_id)
        if not report:
            return {'error': 'Relatório não encontrado'}
        
        # Gera dados do relatório baseado no tipo
        if report.report_type.value == 'daily_summary':
            data = ReportService.generate_daily_summary(db, report.tenant_id)
        elif report.report_type.value == 'weekly_report':
            data = ReportService.generate_weekly_report(db, report.tenant_id)
        else:
            data = ReportService.generate_daily_summary(db, report.tenant_id)
        
        # TODO: Enviar por e-mail quando SMTP estiver configurado
        # Por enquanto, apenas atualiza o timestamp de último envio
        report.last_sent_at = datetime.utcnow()
        db.commit()
        
        logger.info(f"Relatório {report.name} gerado com sucesso")
        return {'report_id': report_id, 'data': data}
    except Exception as e:
        logger.error(f"Erro ao gerar relatório {report_id}: {e}")
        return {'error': str(e)}
    finally:
        db.close()


@celery_app.task
def send_scheduled_reports(schedule: str):
    """
    Task periódica para enviar relatórios agendados.
    
    Args:
        schedule: 'daily', 'weekly' ou 'monthly'
    """
    db = SessionLocal()
    
    try:
        schedule_enum = ReportSchedule(schedule)
        
        # Busca todos os relatórios ativos com este agendamento
        reports = db.query(Report).filter(
            Report.is_active == True,
            Report.schedule == schedule_enum
        ).all()
        
        results = []
        for report in reports:
            try:
                # Gera e envia o relatório
                result = generate_report_task.delay(str(report.id))
                results.append({'report_id': str(report.id), 'task_id': result.id})
                logger.info(f"Relatório {report.name} enfileirado para envio")
            except Exception as e:
                logger.error(f"Erro ao enfileirar relatório {report.name}: {e}")
        
        return {'schedule': schedule, 'reports_queued': len(results)}
    finally:
        db.close()

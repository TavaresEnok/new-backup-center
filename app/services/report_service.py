from sqlalchemy.orm import Session
from app.models.report import Report, ReportType, ReportSchedule
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from datetime import datetime, timedelta
import uuid
from typing import List, Dict, Any, Optional


class ReportService:
    """Serviço para geração e gerenciamento de relatórios."""

    @staticmethod
    def get_tenant_reports(db: Session, tenant_id) -> List[Report]:
        """Retorna todos os relatórios de um tenant."""
        return db.query(Report).filter(
            Report.tenant_id == tenant_id,
        ).order_by(Report.name).all()

    @staticmethod
    def get_report(db: Session, report_id: str) -> Optional[Report]:
        """Retorna um relatório específico."""
        try:
            return db.query(Report).filter(Report.id == uuid.UUID(report_id)).first()
        except ValueError:
            return None

    @staticmethod
    def create_report(db: Session, tenant_id, data: dict) -> Report:
        """Cria um novo relatório."""
        report = Report(
            tenant_id=tenant_id,
            name=data['name'],
            report_type=ReportType(data.get('report_type', 'daily_summary')),
            schedule=ReportSchedule(data.get('schedule', 'daily')),
            recipients=data.get('recipients', []),
            is_active=data.get('is_active', True)
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        return report

    @staticmethod
    def update_report(db: Session, report_id: str, data: dict) -> Optional[Report]:
        """Atualiza um relatório existente."""
        report = ReportService.get_report(db, report_id)
        if not report:
            return None
        
        for key, value in data.items():
            if hasattr(report, key):
                if key == 'report_type':
                    value = ReportType(value)
                elif key == 'schedule':
                    value = ReportSchedule(value)
                setattr(report, key, value)
        
        db.commit()
        db.refresh(report)
        return report

    @staticmethod
    def delete_report(db: Session, report_id: str) -> bool:
        """Remove um relatório."""
        report = ReportService.get_report(db, report_id)
        if not report:
            return False
        db.delete(report)
        db.commit()
        return True

    @staticmethod
    def generate_daily_summary(db: Session, tenant_id) -> Dict[str, Any]:
        """Gera resumo diário de backups."""
        today = datetime.utcnow().date()
        yesterday = today - timedelta(days=1)
        
        # Backups realizados hoje
        backups_today = db.query(Backup).join(Device).filter(
            Device.tenant_id == tenant_id,
            Backup.created_at >= datetime.combine(today, datetime.min.time())
        ).all()
        
        success_count = sum(1 for b in backups_today if b.status == BackupStatus.SUCCESS)
        failed_count = sum(1 for b in backups_today if b.status == BackupStatus.FAILED)
        
        # Dispositivos com falha
        failed_devices = [b.device.name for b in backups_today if b.status == BackupStatus.FAILED]
        
        return {
            'date': today.strftime('%d/%m/%Y'),
            'total_backups': len(backups_today),
            'success_count': success_count,
            'failed_count': failed_count,
            'success_rate': round(success_count / len(backups_today) * 100, 1) if backups_today else 0,
            'failed_devices': failed_devices
        }

    @staticmethod
    def generate_weekly_report(db: Session, tenant_id) -> Dict[str, Any]:
        """Gera relatório semanal detalhado."""
        today = datetime.utcnow().date()
        week_ago = today - timedelta(days=7)
        
        backups = db.query(Backup).join(Device).filter(
            Device.tenant_id == tenant_id,
            Backup.created_at >= datetime.combine(week_ago, datetime.min.time())
        ).all()
        
        # Agrupa por dia
        daily_stats = {}
        for backup in backups:
            day = backup.created_at.date()
            if day not in daily_stats:
                daily_stats[day] = {'success': 0, 'failed': 0}
            if backup.status == BackupStatus.SUCCESS:
                daily_stats[day]['success'] += 1
            else:
                daily_stats[day]['failed'] += 1
        
        return {
            'period': f"{week_ago.strftime('%d/%m')} - {today.strftime('%d/%m/%Y')}",
            'total_backups': len(backups),
            'daily_stats': {k.strftime('%d/%m'): v for k, v in daily_stats.items()},
            'devices_count': len(set(b.device_id for b in backups))
        }

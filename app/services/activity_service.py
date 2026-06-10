from sqlalchemy.orm import Session
from app.models.activity_log import ActivityLog
from typing import Optional, Dict, Any
import json
from datetime import datetime, timedelta
from flask import has_request_context, request, g

class ActivityService:
    @staticmethod
    def _safe_json_dumps(payload: Dict[str, Any]) -> str:
        return json.dumps(payload, ensure_ascii=False, default=str)

    @staticmethod
    def _current_request_id() -> Optional[str]:
        if not has_request_context():
            return None
        rid = getattr(g, "request_id", None)
        if rid:
            return str(rid)
        header_rid = (request.headers.get("X-Request-ID") or "").strip()
        return header_rid or None

    @staticmethod
    def _normalize_details(details: Any) -> Optional[str]:
        if details is None:
            return None

        if isinstance(details, dict):
            payload = dict(details)
        elif isinstance(details, str):
            text = details.strip()
            if not text:
                payload = {}
            else:
                try:
                    parsed = json.loads(text)
                    payload = parsed if isinstance(parsed, dict) else {"message": text}
                except Exception:
                    payload = {"message": text}
        else:
            payload = {"message": str(details)}

        payload.setdefault("resource_type", None)
        payload.setdefault("resource_id", None)
        payload.setdefault("result", None)
        payload.setdefault("message", "")
        payload.setdefault("request_id", ActivityService._current_request_id())
        return ActivityService._safe_json_dumps(payload)

    @staticmethod
    def log_action(db: Session, tenant_id: str, user_id: str, action: str, details: Any = None, ip_address: str = None):
        """
        Registra uma ação no log de atividades.
        """
        import uuid
        if isinstance(tenant_id, str):
            tenant_id = uuid.UUID(tenant_id)
        if isinstance(user_id, str):
            user_id = uuid.UUID(user_id)
        if not ip_address and has_request_context():
            ip_address = request.remote_addr
            
        log = ActivityLog(
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            details=ActivityService._normalize_details(details),
            ip_address=ip_address
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    @staticmethod
    def get_tenant_logs(db: Session, tenant_id: str, limit: int = 100):
        """
        Retorna os últimos logs do tenant.
        """
        return db.query(ActivityLog).filter(
            ActivityLog.tenant_id == tenant_id
        ).order_by(ActivityLog.created_at.desc()).limit(limit).all()

    @staticmethod
    def prune_old_logs(db: Session, retention_days: int, dry_run: bool = True) -> int:
        retention_days = max(int(retention_days or 0), 1)
        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        query = db.query(ActivityLog).filter(ActivityLog.created_at < cutoff)
        total = query.count()
        if dry_run or total == 0:
            return total
        query.delete(synchronize_session=False)
        db.commit()
        return total

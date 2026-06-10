import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import redis

from app.core.config import settings

logger = logging.getLogger(__name__)

_redis_client = None
_global_prune_cache_until = 0.0

TASK_LOG_PREFIX = "backup_center:task_logs:"
TASK_LOG_SEQ_PREFIX = "backup_center:task_logs_seq:"
TASK_META_PREFIX = "backup_center:task_meta:"
TENANT_ACTIVE_BULK_PREFIX = "backup_center:tenant_active_bulk:"
GLOBAL_LOG_KEY = "backup_center:global_logs"
GLOBAL_LOG_SEQ_KEY = "backup_center:global_logs_seq"
def _retention_seconds() -> int:
    days = max(int(getattr(settings, "REALTIME_LOG_RETENTION_DAYS", 90) or 90), 1)
    return days * 24 * 60 * 60


TTL_SECONDS = _retention_seconds()
TASK_LOG_MAX_ENTRIES = max(int(os.getenv("REALTIME_TASK_LOG_MAX_ENTRIES", "2000") or 2000), 200)
GLOBAL_LOG_MAX_ENTRIES = max(int(os.getenv("REALTIME_GLOBAL_LOG_MAX_ENTRIES", "50000") or 50000), 1000)
BULK_ACTIVE_LOCK_TTL_SECONDS = max(
    int(os.getenv("BULK_ACTIVE_LOCK_TTL_SECONDS", "1800") or 1800),
    300,
)


def _tenant_bulk_single_lock_enabled() -> bool:
    return str(
        os.getenv("BULK_TENANT_SINGLE_ACTIVE_LOCK_ENABLED", "0") or "0"
    ).strip().lower() in {"1", "true", "on", "yes", "sim"}


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def get_redis_client():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        _redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        _redis_client.ping()
        return _redis_client
    except Exception:
        logger.exception("Falha ao conectar Redis para realtime logs")
        _redis_client = None
        return None


def _task_log_key(task_id: str) -> str:
    return f"{TASK_LOG_PREFIX}{task_id}"


def _task_log_seq_key(task_id: str) -> str:
    return f"{TASK_LOG_SEQ_PREFIX}{task_id}"


def _task_meta_key(task_id: str) -> str:
    return f"{TASK_META_PREFIX}{task_id}"


def _tenant_active_bulk_key(tenant_id: str) -> str:
    return f"{TENANT_ACTIVE_BULK_PREFIX}{tenant_id}"


def release_tenant_bulk_lock(tenant_id: str | None, task_id: str | None = None) -> None:
    client = get_redis_client()
    if not client or not tenant_id:
        return
    key = _tenant_active_bulk_key(str(tenant_id))
    try:
        current = client.get(key)
        if task_id and current and str(current) != str(task_id):
            return
        client.delete(key)
    except Exception:
        logger.exception("Falha ao liberar lock de lote bulk tenant=%s task=%s", tenant_id, task_id)


def acquire_tenant_bulk_lock(tenant_id: str, task_id: str) -> tuple[bool, str | None]:
    if not _tenant_bulk_single_lock_enabled():
        return True, None

    client = get_redis_client()
    if not client or not tenant_id or not task_id:
        return True, None

    key = _tenant_active_bulk_key(str(tenant_id))
    try:
        existing = client.get(key)
        if existing:
            meta = get_task_meta(str(existing))
            if meta and bool(meta.get("is_bulk")) and not bool(meta.get("completed")):
                return False, str(existing)
            if not meta:
                return False, str(existing)
            client.delete(key)
        acquired = client.set(key, str(task_id), nx=True, ex=BULK_ACTIVE_LOCK_TTL_SECONDS)
        if acquired:
            return True, None
        existing = client.get(key)
        return False, str(existing) if existing else None
    except Exception:
        logger.exception("Falha ao adquirir lock de lote bulk tenant=%s task=%s", tenant_id, task_id)
        return True, None


def register_task(
    task_id: str,
    tenant_id: str,
    device_id: Optional[str] = None,
    device_name: Optional[str] = None,
    group_id: Optional[str] = None,
) -> None:
    if not task_id:
        return
    payload = {
        "task_id": str(task_id),
        "tenant_id": str(tenant_id),
        "device_id": str(device_id) if device_id else None,
        "device_name": device_name or "Dispositivo",
        "group_id": str(group_id) if group_id else None,
        "status": "queued",
        "progress": 0,
        "message": "Task enfileirada, aguardando worker...",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "completed": False,
    }
    _write_task_meta(task_id, payload)


def _write_task_meta(task_id: str, payload: Dict[str, Any]) -> None:
    client = get_redis_client()
    if not client:
        return
    key = _task_meta_key(task_id)
    try:
        client.setex(key, TTL_SECONDS, json.dumps(payload, ensure_ascii=False))
        if _tenant_bulk_single_lock_enabled() and payload.get("is_bulk") and payload.get("tenant_id"):
            tenant_id = str(payload.get("tenant_id"))
            if payload.get("completed"):
                release_tenant_bulk_lock(tenant_id, str(task_id))
            else:
                client.setex(_tenant_active_bulk_key(tenant_id), BULK_ACTIVE_LOCK_TTL_SECONDS, str(task_id))
    except Exception:
        logger.exception("Falha ao salvar task meta %s", task_id)


def get_task_meta(task_id: str) -> Dict[str, Any]:
    client = get_redis_client()
    if not client or not task_id:
        return {}
    try:
        raw = client.get(_task_meta_key(task_id))
        if not raw:
            return {}
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        logger.exception("Falha ao ler task meta %s", task_id)
        return {}


def update_task_meta(task_id: str, **fields: Any) -> Dict[str, Any]:
    if not task_id:
        return {}
    current = get_task_meta(task_id)
    current.update(fields)
    current["task_id"] = str(task_id)
    current["updated_at"] = _now_iso()
    _write_task_meta(task_id, current)
    return current


def append_task_log(
    task_id: Optional[str],
    device_name: str,
    message: str,
    level: str = "info",
) -> None:
    if not task_id:
        return

    client = get_redis_client()
    if not client:
        return

    level = (level or "info").lower().strip()
    if level not in {"info", "success", "warning", "error"}:
        level = "info"
    try:
        from app.utils.log_sanitizer import sanitize_operational_message

        message = sanitize_operational_message(message)
    except Exception:
        message = str(message or "")

    try:
        task_meta = get_task_meta(str(task_id))
        seq = int(client.incr(_task_log_seq_key(task_id)))
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = {
            "task_id": str(task_id),
            "seq": seq,
            "tenant_id": task_meta.get("tenant_id"),
            "device_name": device_name or "Sistema",
            "message": message,
            "level": level,
            "timestamp": timestamp,
            "timestamp_iso": _now_iso(),
        }
        global_seq = int(client.incr(GLOBAL_LOG_SEQ_KEY))
        entry["global_seq"] = global_seq
        serialized = json.dumps(entry, ensure_ascii=False)

        task_key = _task_log_key(task_id)
        client.rpush(task_key, serialized)
        client.ltrim(task_key, -TASK_LOG_MAX_ENTRIES, -1)
        client.expire(task_key, TTL_SECONDS)
        client.expire(_task_log_seq_key(task_id), TTL_SECONDS)

        client.rpush(GLOBAL_LOG_KEY, serialized)
        try:
            _maybe_prune_global_logs_by_age(client)
        except Exception:
            logger.exception("Falha ao podar log global realtime")
        finally:
            client.ltrim(GLOBAL_LOG_KEY, -GLOBAL_LOG_MAX_ENTRIES, -1)
            client.expire(GLOBAL_LOG_KEY, TTL_SECONDS)
            client.expire(GLOBAL_LOG_SEQ_KEY, TTL_SECONDS)
    except Exception:
        logger.exception("Falha ao gravar log realtime task=%s", task_id)


def _parse_iso_timestamp(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    try:
        value = str(raw).strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _global_prune_interval_seconds() -> float:
    raw = str(os.getenv("REALTIME_GLOBAL_PRUNE_INTERVAL_SECONDS", "300")).strip()
    try:
        value = float(raw)
    except Exception:
        value = 300.0
    return max(30.0, min(value, 3600.0))


def _maybe_prune_global_logs_by_age(client) -> int:
    global _global_prune_cache_until

    now_mono = time.monotonic()
    if now_mono < _global_prune_cache_until:
        return 0

    removed = _prune_global_logs_by_age(client)
    _global_prune_cache_until = now_mono + _global_prune_interval_seconds()
    return removed


def _prune_global_logs_by_age(client) -> int:
    removed = 0
    cutoff = _utc_now() - timedelta(days=max(int(getattr(settings, "REALTIME_LOG_RETENTION_DAYS", 90) or 90), 1))

    while True:
        raw = client.lindex(GLOBAL_LOG_KEY, 0)
        if not raw:
            break
        try:
            item = json.loads(raw)
        except Exception:
            client.lpop(GLOBAL_LOG_KEY)
            removed += 1
            continue

        ts = _parse_iso_timestamp(item.get("created_at") or item.get("timestamp_iso"))
        if ts is None:
            # Entradas antigas sem timestamp ISO nao podem ser mantidas sob regra de 90 dias.
            client.lpop(GLOBAL_LOG_KEY)
            removed += 1
            continue
        if ts >= cutoff:
            break
        client.lpop(GLOBAL_LOG_KEY)
        removed += 1
    return removed


def prune_global_logs(retention_days: int = 90, dry_run: bool = True) -> int:
    client = get_redis_client()
    if not client:
        return 0
    retention_days = max(int(retention_days or 0), 1)
    cutoff = _utc_now() - timedelta(days=retention_days)

    raw_entries = client.lrange(GLOBAL_LOG_KEY, 0, -1) or []
    if not raw_entries:
        return 0

    keep = []
    removed = 0
    for raw in raw_entries:
        try:
            item = json.loads(raw)
        except Exception:
            removed += 1
            continue
        ts = _parse_iso_timestamp(item.get("created_at") or item.get("timestamp_iso"))
        if ts is None or ts < cutoff:
            removed += 1
            continue
        keep.append(raw)

    if dry_run:
        return removed

    pipe = client.pipeline()
    pipe.delete(GLOBAL_LOG_KEY)
    if keep:
        pipe.rpush(GLOBAL_LOG_KEY, *keep)
    pipe.expire(GLOBAL_LOG_KEY, _retention_seconds())
    pipe.execute()
    return removed


def _scan_recent_entries(
    client,
    key: str,
    *,
    seq_field: str,
    seq_key: Optional[str] = None,
    after_seq: int = 0,
    limit: int = 200,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    if seq_key:
        try:
            latest_raw = client.get(seq_key)
            latest_seq = int(latest_raw or 0)
        except Exception:
            latest_seq = 0
        if latest_seq > 0 and after_seq >= latest_seq:
            return {"entries": [], "last_seq": latest_seq}

    try:
        total = int(client.llen(key) or 0)
    except Exception:
        logger.exception("Falha ao contar logs key=%s", key)
        return {"entries": [], "last_seq": after_seq}

    if total <= 0:
        return {"entries": [], "last_seq": after_seq}

    chunk_size = max(limit * 4, 500)
    end = total - 1
    last_seq = after_seq
    entries_reversed: List[Dict[str, Any]] = []
    reached_boundary = False

    while end >= 0 and len(entries_reversed) < limit and not reached_boundary:
        start = max(0, end - chunk_size + 1)
        try:
            raw_entries = client.lrange(key, start, end) or []
        except Exception:
            logger.exception("Falha ao ler logs key=%s", key)
            return {"entries": [], "last_seq": after_seq}

        if not raw_entries:
            break

        for raw in reversed(raw_entries):
            try:
                item = json.loads(raw)
            except Exception:
                continue
            if not isinstance(item, dict):
                continue
            seq = int(item.get(seq_field, 0) or 0)
            if seq <= after_seq:
                reached_boundary = True
                break
            if tenant_id and str(item.get("tenant_id") or "") != str(tenant_id):
                continue
            entries_reversed.append(item)
            if seq > last_seq:
                last_seq = seq
            if len(entries_reversed) >= limit:
                break

        if start == 0:
            break
        end = start - 1

    entries = list(reversed(entries_reversed[-limit:]))
    return {"entries": entries, "last_seq": last_seq}


def get_task_logs(task_id: str, after_seq: int = 0, limit: int = 200) -> Dict[str, Any]:
    client = get_redis_client()
    if not client or not task_id:
        return {"entries": [], "last_seq": after_seq}
    return _scan_recent_entries(
        client,
        _task_log_key(task_id),
        seq_field="seq",
        seq_key=_task_log_seq_key(task_id),
        after_seq=after_seq,
        limit=limit,
    )


def get_global_logs(after_seq: int = 0, limit: int = 300, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    client = get_redis_client()
    if not client:
        return {"entries": [], "last_seq": after_seq}
    return _scan_recent_entries(
        client,
        GLOBAL_LOG_KEY,
        seq_field="global_seq",
        seq_key=GLOBAL_LOG_SEQ_KEY,
        after_seq=after_seq,
        limit=limit,
        tenant_id=tenant_id,
    )


def clear_tenant_global_logs(tenant_id: str) -> int:
    """Remove entradas do stream global de logs para um tenant específico."""
    client = get_redis_client()
    if not client or not tenant_id:
        return 0

    try:
        raw_entries = client.lrange(GLOBAL_LOG_KEY, 0, -1) or []
    except Exception:
        logger.exception("Falha ao listar logs globais para limpeza tenant=%s", tenant_id)
        return 0

    if not raw_entries:
        return 0

    target_tenant = str(tenant_id)
    kept_entries: List[str] = []
    removed = 0

    for raw in raw_entries:
        try:
            item = json.loads(raw)
        except Exception:
            # Mantém lixo de parsing sujeito à retenção normal para não apagar dados de outros tenants.
            kept_entries.append(raw)
            continue

        if str(item.get("tenant_id") or "") == target_tenant:
            removed += 1
            continue
        kept_entries.append(raw)

    if removed <= 0:
        return 0

    try:
        pipe = client.pipeline()
        pipe.delete(GLOBAL_LOG_KEY)
        if kept_entries:
            pipe.rpush(GLOBAL_LOG_KEY, *kept_entries)
            pipe.expire(GLOBAL_LOG_KEY, _retention_seconds())
        pipe.execute()
    except Exception:
        logger.exception("Falha ao regravar logs globais na limpeza tenant=%s", tenant_id)
        return 0

    return removed

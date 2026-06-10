import json
import math
import os
import time
from typing import Dict, Iterable, Tuple

from app.services.realtime_backup_logs import get_redis_client


METRIC_PREFIX = "backup_center:metrics"
QUEUE_NAMES = ("celery", "jump_queue", "vpn_queue")

HISTOGRAM_BUCKETS: Dict[str, Tuple[float, ...]] = {
    "backup_task_duration_seconds": (1, 2, 5, 10, 20, 30, 60, 120, 300, 600, 1200),
    "backup_script_duration_seconds": (0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300, 600, 1200),
    "backup_precheck_duration_seconds": (0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 30),
    "jump_host_wait_seconds": (0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 30, 60, 120, 180, 300),
}

METRICS_HELP: Dict[str, Tuple[str, str]] = {
    "backup_task_total": ("counter", "Backup task outcomes grouped by category."),
    "backup_retry_total": ("counter", "Automatic retry count for backup tasks."),
    "backup_script_total": ("counter", "Backup script outcomes grouped by script/device type."),
    "backup_precheck_total": ("counter", "Network precheck outcomes before running backup scripts."),
    "bulk_preflight_devices_total": ("counter", "Bulk preflight classification counts."),
    "jump_host_slot_acquire_total": ("counter", "Jump host slot acquire outcomes."),
    "jump_host_adaptive_slot_changes_total": ("counter", "Adaptive slot changes per jump host."),
    "backup_task_duration_seconds": ("histogram", "Backup task runtime in seconds."),
    "backup_script_duration_seconds": ("histogram", "Backup script runtime in seconds."),
    "backup_precheck_duration_seconds": ("histogram", "Duration of network precheck before backup."),
    "jump_host_wait_seconds": ("histogram", "Wait time to acquire jump host slot."),
    "celery_queue_depth": ("gauge", "Current queue depth from Redis broker lists."),
    "celery_worker_up": ("gauge", "Celery worker availability from inspect."),
    "celery_worker_active_tasks": ("gauge", "Number of active tasks per Celery worker."),
    "celery_worker_reserved_tasks": ("gauge", "Number of reserved tasks per Celery worker."),
    "celery_worker_scheduled_tasks": ("gauge", "Number of scheduled tasks per Celery worker."),
    "celery_worker_pool_processes": ("gauge", "Pool process count per Celery worker."),
}

# Avoid unbounded cardinality in metrics labels; high-cardinality labels (host, device, task)
# explode Redis hashes and make /internal/metrics/backups expensive.
ALLOWED_LABEL_KEYS = {
    "tenant_id",
    "outcome",
    "category",
    "device_type",
    "script_name",
    "queue",
    "worker",
    "classification",
    "jump_host",
    "result",
    "operation_kind",
}

_METRICS_CACHE_PAYLOAD: str = ""
_METRICS_CACHE_UNTIL: float = 0.0
_CELERY_RUNTIME_CACHE_UNTIL: float = 0.0


def _sanitize_metric_name(name: str) -> str:
    safe = []
    for ch in str(name or "").strip():
        if ch.isalnum() or ch in ("_", ":"):
            safe.append(ch)
        else:
            safe.append("_")
    return "".join(safe).strip("_") or "metric"


def _normalize_label_value(value) -> str:
    text = str(value if value is not None else "unknown")
    text = text.replace("\\", "\\\\").replace("\n", " ").replace('"', '\\"')
    return text


def _normalize_labels(labels: Dict[str, str] | None) -> Dict[str, str]:
    normalized = {}
    for key, value in sorted((labels or {}).items()):
        safe_key = _sanitize_metric_name(key)
        if not safe_key:
            continue
        if safe_key not in ALLOWED_LABEL_KEYS:
            continue
        normalized[safe_key] = _normalize_label_value(value)
    return normalized


def _labels_key(labels: Dict[str, str] | None) -> str:
    normalized = _normalize_labels(labels)
    if not normalized:
        return "-"
    return json.dumps(normalized, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _counter_key(metric_name: str) -> str:
    return f"{METRIC_PREFIX}:counter:{_sanitize_metric_name(metric_name)}"


def _gauge_key(metric_name: str) -> str:
    return f"{METRIC_PREFIX}:gauge:{_sanitize_metric_name(metric_name)}"


def _histogram_bucket_key(metric_name: str) -> str:
    return f"{METRIC_PREFIX}:hist:{_sanitize_metric_name(metric_name)}:bucket"


def _histogram_count_key(metric_name: str) -> str:
    return f"{METRIC_PREFIX}:hist:{_sanitize_metric_name(metric_name)}:count"


def _histogram_sum_key(metric_name: str) -> str:
    return f"{METRIC_PREFIX}:hist:{_sanitize_metric_name(metric_name)}:sum"


def inc_counter(metric_name: str, value: float = 1.0, labels: Dict[str, str] | None = None) -> None:
    if value is None:
        return
    try:
        delta = float(value)
    except Exception:
        return
    if math.isnan(delta) or math.isinf(delta):
        return
    client = get_redis_client()
    if not client:
        return
    try:
        client.hincrbyfloat(_counter_key(metric_name), _labels_key(labels), delta)
    except Exception:
        pass


def set_gauge(metric_name: str, value: float, labels: Dict[str, str] | None = None) -> None:
    try:
        numeric = float(value)
    except Exception:
        return
    if math.isnan(numeric) or math.isinf(numeric):
        return
    client = get_redis_client()
    if not client:
        return
    try:
        client.hset(_gauge_key(metric_name), _labels_key(labels), numeric)
    except Exception:
        pass


def observe_histogram(metric_name: str, value: float, labels: Dict[str, str] | None = None) -> None:
    buckets = HISTOGRAM_BUCKETS.get(metric_name)
    if not buckets:
        return
    try:
        numeric = float(value)
    except Exception:
        return
    if numeric < 0 or math.isnan(numeric) or math.isinf(numeric):
        return
    client = get_redis_client()
    if not client:
        return
    label_key = _labels_key(labels)
    try:
        pipe = client.pipeline()
        pipe.hincrbyfloat(_histogram_sum_key(metric_name), label_key, numeric)
        pipe.hincrby(_histogram_count_key(metric_name), label_key, 1)
        for bound in buckets:
            if numeric <= bound:
                field = f"{label_key}|le={bound}"
                pipe.hincrby(_histogram_bucket_key(metric_name), field, 1)
        pipe.hincrby(_histogram_bucket_key(metric_name), f"{label_key}|le=+Inf", 1)
        pipe.execute()
    except Exception:
        pass


def _parse_labels_key(serialized: str) -> Dict[str, str]:
    if not serialized or serialized == "-":
        return {}
    try:
        parsed = json.loads(serialized)
        if isinstance(parsed, dict):
            return {str(k): str(v) for k, v in parsed.items()}
    except Exception:
        pass
    return {}


def _labels_text(labels: Dict[str, str]) -> str:
    if not labels:
        return ""
    parts = [f'{k}="{v}"' for k, v in sorted(labels.items())]
    return "{" + ",".join(parts) + "}"


def _iter_hash_items(client, key: str) -> Iterable[Tuple[str, float]]:
    try:
        raw = client.hgetall(key) or {}
    except Exception:
        return []
    rows = []
    for field, value in raw.items():
        try:
            rows.append((str(field), float(value)))
        except Exception:
            continue
    return rows


def refresh_broker_queue_depth() -> None:
    client = get_redis_client()
    if not client:
        return
    for queue_name in QUEUE_NAMES:
        size = 0
        try:
            size = int(client.llen(queue_name) or 0)
        except Exception:
            size = 0
        set_gauge("celery_queue_depth", size, {"queue": queue_name})


def refresh_celery_runtime_metrics() -> None:
    global _CELERY_RUNTIME_CACHE_UNTIL

    if str(os.getenv("CELERY_METRICS_INSPECT_ENABLED", "0")).strip().lower() not in {"1", "true", "on", "yes"}:
        return
    refresh_every = float(str(os.getenv("CELERY_METRICS_INSPECT_REFRESH_SECONDS", "30")).strip() or 30.0)
    refresh_every = max(5.0, min(refresh_every, 120.0))
    now_ts = time.monotonic()
    if now_ts < _CELERY_RUNTIME_CACHE_UNTIL:
        return
    try:
        from app.celery_app import celery_app
    except Exception:
        return

    try:
        inspector = celery_app.control.inspect(timeout=1)
        stats = inspector.stats() or {}
        active = inspector.active() or {}
        reserved = inspector.reserved() or {}
        scheduled = inspector.scheduled() or {}
    except Exception:
        return

    workers = set(stats.keys()) | set(active.keys()) | set(reserved.keys()) | set(scheduled.keys())
    for worker in workers:
        labels = {"worker": str(worker)}
        set_gauge("celery_worker_up", 1, labels=labels)
        set_gauge("celery_worker_active_tasks", len(active.get(worker) or []), labels=labels)
        set_gauge("celery_worker_reserved_tasks", len(reserved.get(worker) or []), labels=labels)
        set_gauge("celery_worker_scheduled_tasks", len(scheduled.get(worker) or []), labels=labels)
        pool = (stats.get(worker) or {}).get("pool") or {}
        set_gauge("celery_worker_pool_processes", int(pool.get("max-concurrency") or 0), labels=labels)
    _CELERY_RUNTIME_CACHE_UNTIL = time.monotonic() + refresh_every


def render_prometheus_metrics() -> str:
    global _METRICS_CACHE_PAYLOAD, _METRICS_CACHE_UNTIL

    cache_ttl = float(str(os.getenv("BACKUP_METRICS_CACHE_SECONDS", "20")).strip() or 20.0)
    cache_ttl = max(1.0, min(cache_ttl, 60.0))
    now_ts = time.monotonic()
    if _METRICS_CACHE_PAYLOAD and now_ts < _METRICS_CACHE_UNTIL:
        return _METRICS_CACHE_PAYLOAD

    client = get_redis_client()
    if not client:
        return ""

    refresh_broker_queue_depth()
    refresh_celery_runtime_metrics()
    lines = []

    for metric_name, (metric_type, help_text) in METRICS_HELP.items():
        safe_name = _sanitize_metric_name(metric_name)
        lines.append(f"# HELP {safe_name} {help_text}")
        lines.append(f"# TYPE {safe_name} {metric_type}")

        if metric_type == "counter":
            for field, value in _iter_hash_items(client, _counter_key(metric_name)):
                labels = _parse_labels_key(field)
                lines.append(f"{safe_name}{_labels_text(labels)} {value}")
            continue

        if metric_type == "gauge":
            for field, value in _iter_hash_items(client, _gauge_key(metric_name)):
                labels = _parse_labels_key(field)
                lines.append(f"{safe_name}{_labels_text(labels)} {value}")
            continue

        if metric_type == "histogram":
            bucket_map: Dict[Tuple[str, str], float] = {}
            for field, value in _iter_hash_items(client, _histogram_bucket_key(metric_name)):
                if "|le=" not in field:
                    continue
                label_key, le_raw = field.rsplit("|le=", 1)
                bucket_map[(label_key, le_raw)] = value
            count_rows = list(_iter_hash_items(client, _histogram_count_key(metric_name)))
            sum_rows = dict(_iter_hash_items(client, _histogram_sum_key(metric_name)))
            for label_key, count in count_rows:
                labels = _parse_labels_key(label_key)
                for bound in HISTOGRAM_BUCKETS.get(metric_name, ()):
                    bound_text = str(bound)
                    bucket_labels = dict(labels)
                    bucket_labels["le"] = bound_text
                    bucket_val = bucket_map.get((label_key, bound_text), 0.0)
                    lines.append(f"{safe_name}_bucket{_labels_text(bucket_labels)} {bucket_val}")
                inf_labels = dict(labels)
                inf_labels["le"] = "+Inf"
                inf_val = bucket_map.get((label_key, "+Inf"), 0.0)
                lines.append(f"{safe_name}_bucket{_labels_text(inf_labels)} {inf_val}")

                lines.append(f"{safe_name}_sum{_labels_text(labels)} {sum_rows.get(label_key, 0.0)}")
                lines.append(f"{safe_name}_count{_labels_text(labels)} {count}")

    payload = "\n".join(lines) + ("\n" if lines else "")
    _METRICS_CACHE_PAYLOAD = payload
    _METRICS_CACHE_UNTIL = time.monotonic() + cache_ttl
    return payload


def metrics_token_is_valid(request_header_token: str | None) -> bool:
    expected = str(os.getenv("BACKUP_METRICS_TOKEN", "") or "").strip()
    if not expected:
        return True
    candidate = str(request_header_token or "").strip()
    if candidate.lower().startswith("bearer "):
        candidate = candidate[7:].strip()
    return candidate == expected

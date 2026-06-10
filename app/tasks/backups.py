"""
Tasks Celery para execução de backups.

Essas tasks executam em background para não bloquear o servidor web.
"""

from app.celery_app import celery_app
from app.core.database import SessionLocal
from app.core.config import settings
from app.services.connection_mode import uses_jump_host, uses_vpn_tunnel
from app.services.backup_observability import inc_counter, observe_histogram
import logging
import math
import os
import json
import signal
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import time
from contextlib import contextmanager
from celery.exceptions import Retry
from app.services.schedule_utils import compute_next_daily_run_at, sanitize_daily_time, utc_now_naive
from app.services.mass_backup_scope import resolve_mass_backup_excluded_type_ids
from app.services.activity_service import ActivityService

logger = logging.getLogger(__name__)
LARGE_BULK_FAIL_FAST_THRESHOLD = 8
CB_FAILURE_CATEGORIES = {
    "timeout",
    "connection",
    "jump_session_closed",
    "port_refused",
    "no_ping",
    "jump_host_slot_timeout",
}


def _safe_error_text(err, fallback: str = "Erro sem detalhe.") -> str:
    """Normaliza mensagens de erro para evitar logs vazios ('')."""
    if err is None:
        return fallback
    try:
        txt = str(err).strip()
    except Exception:
        txt = ""
    if txt:
        return txt
    name = getattr(getattr(err, "__class__", None), "__name__", "") or ""
    return name or fallback


def _env_int(name: str, default: int, *, minimum: int = 0, maximum: int | None = None) -> int:
    raw = str(os.getenv(name, default)).strip()
    try:
        value = int(raw)
    except Exception:
        value = int(default)
    if value < minimum:
        value = minimum
    if maximum is not None and value > maximum:
        value = maximum
    return value


def _env_bool(name: str, default: str = "0") -> bool:
    return str(os.getenv(name, default) or "").strip().lower() in {"1", "true", "on", "yes", "sim"}


def _normalize_retry_token(value: str | None) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _env_csv_normalized_set(name: str, default: str = "") -> set[str]:
    raw = str(os.getenv(name, default) or "")
    parsed: set[str] = set()
    for chunk in raw.split(","):
        token = _normalize_retry_token(chunk)
        if token:
            parsed.add(token)
    return parsed


JUMP_HOST_LOCK_TIMEOUT_SECONDS = _env_int(
    "JUMP_HOST_SLOT_TTL_SECONDS",
    60 * 11,
    minimum=60,
)
JUMP_HOST_LOCK_WAIT_SECONDS = _env_int(
    "JUMP_HOST_SLOT_WAIT_SECONDS",
    60 * 10,
    minimum=15,
    maximum=60 * 30,
)
JUMP_HOST_LOCK_WAIT_SECONDS_LARGE_BULK = _env_int(
    "JUMP_HOST_SLOT_WAIT_SECONDS_LARGE_BULK",
    60 * 15,
    minimum=60,
    maximum=60 * 60,
)
JUMP_HOST_MAX_SLOTS = _env_int(
    "JUMP_HOST_MAX_SLOTS",
    3,
    minimum=1,
    maximum=16,
)
JUMP_PHASE_GROUP_STAGGER_SECONDS = _env_int(
    "JUMP_PHASE_GROUP_STAGGER_SECONDS",
    2,
    minimum=0,
    maximum=30,
)
BACKUP_TASK_SOFT_TIME_LIMIT_SECONDS = _env_int(
    "BACKUP_TASK_SOFT_TIME_LIMIT_SECONDS",
    480,
    minimum=120,
    maximum=3600,
)
BACKUP_TASK_TIME_LIMIT_SECONDS = _env_int(
    "BACKUP_TASK_TIME_LIMIT_SECONDS",
    max(BACKUP_TASK_SOFT_TIME_LIMIT_SECONDS + 60, 540),
    minimum=180,
    maximum=3900,
)

LARGE_BULK_TRANSIENT_RETRY_THRESHOLD = _env_int(
    "BULK_TRANSIENT_RETRY_THRESHOLD",
    300,
    minimum=50,
)
LARGE_BULK_TRANSIENT_MAX_RETRIES = _env_int(
    "BULK_TRANSIENT_MAX_RETRIES",
    1,
    minimum=0,
    maximum=2,
)
JUMP_HOST_ADAPTIVE_ENABLED = str(os.getenv("JUMP_HOST_ADAPTIVE_ENABLED", "1")).strip() in {"1", "true", "on", "yes"}
JUMP_HOST_ADAPTIVE_FAIL_STREAK = _env_int("JUMP_HOST_ADAPTIVE_FAIL_STREAK", 4, minimum=2, maximum=20)
JUMP_HOST_ADAPTIVE_SUCCESS_STREAK = _env_int("JUMP_HOST_ADAPTIVE_SUCCESS_STREAK", 20, minimum=5, maximum=200)
JUMP_HOST_ADAPTIVE_COOLDOWN_SECONDS = _env_int("JUMP_HOST_ADAPTIVE_COOLDOWN_SECONDS", 300, minimum=30, maximum=3600)
JUMP_HOST_ADAPTIVE_STREAK_TTL_SECONDS = _env_int("JUMP_HOST_ADAPTIVE_STREAK_TTL_SECONDS", 900, minimum=60, maximum=7200)
JUMP_HOST_ADAPTIVE_MAX_BOOST = _env_int("JUMP_HOST_ADAPTIVE_MAX_BOOST", 2, minimum=0, maximum=8)
JUMP_HOST_ADAPTIVE_SEVERE_FAIL_STREAK = _env_int(
    "JUMP_HOST_ADAPTIVE_SEVERE_FAIL_STREAK",
    2,
    minimum=1,
    maximum=10,
)
JUMP_HOST_ADAPTIVE_SEVERE_COOLDOWN_SECONDS = _env_int(
    "JUMP_HOST_ADAPTIVE_SEVERE_COOLDOWN_SECONDS",
    900,
    minimum=30,
    maximum=7200,
)
JUMP_HOST_ADAPTIVE_SEVERE_DROP_TO_ONE = str(
    os.getenv("JUMP_HOST_ADAPTIVE_SEVERE_DROP_TO_ONE", "1")
).strip().lower() in {"1", "true", "on", "yes"}
BULK_ACTIVE_STALE_SECONDS = _env_int(
    "BULK_ACTIVE_STALE_SECONDS",
    60 * 30,
    minimum=60 * 5,
    maximum=60 * 60 * 48,
)
CIRCUIT_BREAKER_WINDOW_SECONDS = _env_int("CB_WINDOW_SECONDS", 300, minimum=60, maximum=900)
CIRCUIT_BREAKER_THRESHOLD_PERCENT = _env_int("CB_THRESHOLD_PERCENT", 70, minimum=30, maximum=95)
CIRCUIT_BREAKER_MIN_SAMPLES = _env_int("CB_MIN_SAMPLES", 10, minimum=3, maximum=50)
CIRCUIT_BREAKER_OPEN_SECONDS = _env_int("CB_OPEN_SECONDS", 60, minimum=10, maximum=300)
CB_OPEN_MAX_RETRIES = _env_int("CB_OPEN_MAX_RETRIES", 1, minimum=0, maximum=10)
CB_OPEN_RETRY_BUFFER_SECONDS = _env_int("CB_OPEN_RETRY_BUFFER_SECONDS", 2, minimum=0, maximum=30)
VPN_GLOBAL_LOCK_TIMEOUT_SECONDS = _env_int(
    "VPN_GLOBAL_LOCK_TIMEOUT_SECONDS",
    3600,
    minimum=60,
    maximum=60 * 60 * 6,
)
# Tempo maximo que um ÚNICO dispositivo pode consumir dentro da sessão VPN do grupo.
# Evita que um dispositivo travado bloqueie todos os subsequentes enquanto a VPN está aberta.
VPN_GROUP_DEVICE_MAX_SECONDS = _env_int(
    "VPN_GROUP_DEVICE_MAX_SECONDS",
    120,
    minimum=30,
    maximum=480,
)
TRANSIENT_RETRY_DENYLIST_DEVICE_NAMES = _env_csv_normalized_set(
    "BACKUP_TRANSIENT_RETRY_DENYLIST_NAMES",
    "FLASHNET - SW CORE-CABO_S.A.",
)
TRANSIENT_RETRY_DENYLIST_DEVICE_IDS = _env_csv_normalized_set(
    "BACKUP_TRANSIENT_RETRY_DENYLIST_IDS",
    "",
)
BULK_TRANSIENT_FOLLOWUP_ENABLED = _env_bool("BULK_TRANSIENT_FOLLOWUP_ENABLED", "1")
BULK_TRANSIENT_FOLLOWUP_DELAY_SECONDS = _env_int(
    "BULK_TRANSIENT_FOLLOWUP_DELAY_SECONDS",
    600,
    minimum=60,
    maximum=60 * 60 * 6,
)
BULK_TRANSIENT_FOLLOWUP_BUSY_RETRY_SECONDS = _env_int(
    "BULK_TRANSIENT_FOLLOWUP_BUSY_RETRY_SECONDS",
    300,
    minimum=30,
    maximum=60 * 30,
)
BULK_TRANSIENT_FOLLOWUP_MAX_RETRIES = _env_int(
    "BULK_TRANSIENT_FOLLOWUP_MAX_RETRIES",
    12,
    minimum=0,
    maximum=96,
)
AUTO_REPROCESS_JUMP_COUNTDOWN_STEP_SECONDS = 8
AUTO_REPROCESS_DIRECT_GLOBAL_BATCH_SIZE = 25

# Espacamento (segundos) entre dispositivos do MESMO bastion ao enfileirar a fase Jump.
# Combinado com o round-robin por bastion, garante alta concorrencia ENTRE bastions
# (velocidade) sem despejar varias sessoes SSH simultaneas no MESMO bastion (estabilidade).
JUMP_BULK_BASTION_STAGGER_SECONDS = _env_int(
    "JUMP_BULK_BASTION_STAGGER_SECONDS",
    5,
    minimum=0,
    maximum=60,
)
JUMP_HOST_WINDOW_ADAPTIVE_ENABLED = _env_bool("JUMP_HOST_WINDOW_ADAPTIVE_ENABLED", "1")
JUMP_HOST_WINDOW_SECONDS = _env_int(
    "JUMP_HOST_WINDOW_SECONDS",
    1800,
    minimum=300,
    maximum=60 * 60 * 24,
)
JUMP_HOST_WINDOW_MIN_SAMPLES = _env_int(
    "JUMP_HOST_WINDOW_MIN_SAMPLES",
    3,
    minimum=1,
    maximum=100,
)
JUMP_HOST_WINDOW_MIN_SLOTS = _env_int(
    "JUMP_HOST_WINDOW_MIN_SLOTS",
    2,
    minimum=1,
    maximum=16,
)
JUMP_HOST_DURATION_EMA_ALPHA_PERCENT = _env_int(
    "JUMP_HOST_DURATION_EMA_ALPHA_PERCENT",
    25,
    minimum=1,
    maximum=100,
)
JUMP_HOST_DURATION_AVG_TTL_SECONDS = _env_int(
    "JUMP_HOST_DURATION_AVG_TTL_SECONDS",
    60 * 60 * 24 * 14,
    minimum=60 * 60,
    maximum=60 * 60 * 24 * 90,
)

_bulk_device_count_cache: dict[str, int] = {}
_jump_host_slot_overrides_cache: dict[str, int] | None = None


class JumpHostSlotTimeoutError(RuntimeError):
    """Timeout aguardando slot de concorrência em Jump Host compartilhado."""


class JumpHostSlotCancelledError(RuntimeError):
    """Execucao interrompida enquanto aguardava slot do Jump Host."""


class DeviceExecutionDeadlineExceeded(RuntimeError):
    """Timeout local para um dispositivo dentro de uma task de grupo."""


@contextmanager
def _device_execution_deadline(timeout_seconds: int | float):
    try:
        timeout_value = int(timeout_seconds or 0)
    except Exception:
        timeout_value = 0
    if timeout_value <= 0:
        yield
        return

    def _raise_timeout(_signum, _frame):
        raise DeviceExecutionDeadlineExceeded(
            f"Timeout por dispositivo no grupo ({timeout_value}s excedido)."
        )

    try:
        previous_handler = signal.getsignal(signal.SIGALRM)
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        signal.signal(signal.SIGALRM, _raise_timeout)
        signal.setitimer(signal.ITIMER_REAL, timeout_value)
    except Exception:
        yield
        return

    try:
        yield
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
            if previous_timer and float(previous_timer[0] or 0) > 0:
                signal.setitimer(signal.ITIMER_REAL, previous_timer[0], previous_timer[1])
        except Exception:
            pass


def _is_global_backup_stop_enabled() -> bool:
    try:
        from app.services.realtime_backup_logs import get_redis_client
        r = get_redis_client()
        if not r:
            return False
        flag = r.get("backup_center:force_stop_backups")
        return str(flag or "").strip() == "1"
    except Exception:
        logger.exception("Falha ao verificar bloqueio global de backups")
        return False


def _is_bulk_cancelled(bulk_task_id: str | None) -> bool:
    if not bulk_task_id:
        return False
    try:
        from app.services.realtime_backup_logs import get_task_meta
        meta = get_task_meta(str(bulk_task_id))
        return bool(meta.get("cancel_requested"))
    except Exception:
        logger.exception("Falha ao verificar cancelamento do lote %s", bulk_task_id)
        return False


def _should_stop_now(bulk_task_id: str | None = None) -> bool:
    return _is_global_backup_stop_enabled() or _is_bulk_cancelled(bulk_task_id)


def reset_circuit_breakers_for_new_batch() -> dict:
    """
    Limpa o estado residual do circuit breaker entre lotes consecutivos.

    A chave 'cb:open:{jump_label}' bloqueia jump hosts com TTL de 60s. Quando um novo
    lote inicia logo apos um lote com muitas falhas, esses bloqueios ainda estao ativos
    no Redis, rejeitando centenas de tasks sem nem tentar. Esta funcao:

    - Remove chaves 'cb:open:*' (os bloqueios ativos).
    - Remove 'cb:outcomes:*' para evitar contaminação entre lotes.
    - Limpa 'jump_host_adaptive*' (reducoes de slot adaptativo anteriores).

    Retorna dict com contagem de chaves removidas para logging.
    """
    from app.services.realtime_backup_logs import get_redis_client

    client = get_redis_client()
    result = {"open_cleared": 0, "adaptive_cleared": 0, "error": None}
    if not client:
        result["error"] = "Redis indisponivel"
        return result

    try:
        open_keys = list(client.scan_iter("backup_center:cb:open:*"))
        if open_keys:
            client.delete(*open_keys)
            result["open_cleared"] = len(open_keys)

        # Limpar o historico de outcomes evita que falhas do lote anterior
        # contaminem o threshold do proximo lote e causem trips prematuros.
        outcomes_keys = list(client.scan_iter("backup_center:cb:outcomes:*"))
        if outcomes_keys:
            client.delete(*outcomes_keys)
            result["outcomes_cleared"] = len(outcomes_keys)

        adaptive_keys = list(client.scan_iter("backup_center:jump_host_adaptive:*"))
        if adaptive_keys:
            client.delete(*adaptive_keys)
            result["adaptive_cleared"] = len(adaptive_keys)

        logger.info(
            "Circuit breakers resetados para novo lote: %d open keys, %d outcomes, %d adaptive keys removidos.",
            result["open_cleared"],
            result.get("outcomes_cleared", 0),
            result["adaptive_cleared"],
        )
    except Exception as exc:
        logger.exception("Falha ao resetar circuit breakers para novo lote.")
        result["error"] = str(exc)

    return result


def _has_active_bulk_operation() -> bool:
    """Evita concorrencia entre scheduler periodico e backups em massa em andamento."""
    from app.services.realtime_backup_logs import get_redis_client

    client = get_redis_client()
    if not client:
        return False

    now_utc = datetime.utcnow()
    try:
        for key in client.scan_iter("backup_center:tenant_active_bulk:*"):
            task_id = client.get(key)
            if not task_id:
                client.delete(key)
                continue
            raw = client.get(f"backup_center:task_meta:{task_id}")
            if not raw:
                client.delete(key)
                continue
            try:
                meta = json.loads(raw)
            except Exception:
                client.delete(key)
                continue
            if not isinstance(meta, dict):
                client.delete(key)
                continue
            if not bool(meta.get("is_bulk")) or bool(meta.get("completed")):
                client.delete(key)
                continue
            operation_kind = str(meta.get("operation_kind") or "backup_bulk").strip().lower()
            if operation_kind not in {"backup_bulk", "backup_reprocess"}:
                continue

            # Usa o timestamp mais recente de atividade conhecida do lote para evitar
            # que lotes longos sejam tratados como "fantasma" e liberem concorrencia indevida.
            activity_candidates = [
                str(meta.get("last_child_activity_at") or "").strip(),
                str(meta.get("updated_at") or "").strip(),
                str(meta.get("created_at") or "").strip(),
            ]
            latest_activity = None
            for value in activity_candidates:
                if not value:
                    continue
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    continue
                if latest_activity is None or parsed > latest_activity:
                    latest_activity = parsed
            if latest_activity is not None:
                if (now_utc - latest_activity).total_seconds() > BULK_ACTIVE_STALE_SECONDS:
                    client.delete(key)
                    continue
            return True
    except Exception:
        logger.exception("Falha ao verificar lotes bulk ativos antes do scheduler.")
        return False
    return False


def _touch_bulk_activity(bulk_task_id: str | None) -> None:
    if not bulk_task_id:
        return
    try:
        from app.services.realtime_backup_logs import update_task_meta

        update_task_meta(
            str(bulk_task_id),
            last_child_activity_at=datetime.utcnow().isoformat() + "Z",
        )
    except Exception:
        logger.exception("Falha ao atualizar heartbeat do lote %s", bulk_task_id)


def _sleep_with_stop_poll(delay_seconds: int | float, bulk_task_id: str | None = None) -> bool:
    """Espera em pequenos intervalos para permitir cancelamento mais responsivo."""
    remaining = max(0.0, float(delay_seconds or 0))
    while remaining > 0:
        if _should_stop_now(bulk_task_id):
            return True
        step = min(1.0, remaining)
        time.sleep(step)
        remaining -= step
    return _should_stop_now(bulk_task_id)


def _get_bulk_device_count(bulk_task_id: str | None) -> int:
    if not bulk_task_id:
        return 0
    bulk_id = str(bulk_task_id).strip()
    if not bulk_id:
        return 0
    if bulk_id in _bulk_device_count_cache:
        return _bulk_device_count_cache[bulk_id]
    try:
        from app.services.realtime_backup_logs import get_task_meta

        meta = get_task_meta(bulk_id) or {}
        total = int(meta.get("total_devices") or meta.get("total_tasks") or 0)
        total = max(0, total)
        _bulk_device_count_cache[bulk_id] = total
        return total
    except Exception:
        logger.exception("Falha ao obter tamanho do lote %s para politica de retry", bulk_id)
        return 0


def _max_transient_retries_for_bulk(bulk_task_id: str | None) -> int:
    # Politica unificada: cada dispositivo pode retentar no maximo 1x.
    return LARGE_BULK_TRANSIENT_MAX_RETRIES


def _is_large_bulk_operation(bulk_task_id: str | None) -> bool:
    return _get_bulk_device_count(bulk_task_id) >= LARGE_BULK_TRANSIENT_RETRY_THRESHOLD


def _effective_jump_host_wait_seconds(bulk_task_id: str | None) -> int:
    if _is_large_bulk_operation(bulk_task_id):
        return max(60, JUMP_HOST_LOCK_WAIT_SECONDS_LARGE_BULK)
    return JUMP_HOST_LOCK_WAIT_SECONDS


def _bulk_jump_bastion_counts_key(bulk_task_id: str) -> str:
    return f"backup_center:bulk:jump_bastion_counts:{bulk_task_id}"


def _jump_host_duration_avg_key() -> str:
    return "backup_center:jump_host:duration_avg_seconds"


def _jump_host_duration_samples_key() -> str:
    return "backup_center:jump_host:duration_samples"


def _store_bulk_jump_bastion_counts(client, bulk_task_id: str | None, counts: dict[str, int] | Counter) -> None:
    if not client or not bulk_task_id or not counts:
        return
    normalized = {
        str(label): int(count)
        for label, count in dict(counts or {}).items()
        if str(label or "").strip() and int(count or 0) > 0
    }
    if not normalized:
        return
    try:
        key = _bulk_jump_bastion_counts_key(str(bulk_task_id))
        pipe = client.pipeline()
        pipe.delete(key)
        pipe.hset(key, mapping=normalized)
        pipe.expire(key, max(BULK_ACTIVE_STALE_SECONDS * 2, 60 * 60))
        pipe.execute()
    except Exception:
        logger.exception("Falha ao salvar contagem de dispositivos por Jump Host do lote %s", bulk_task_id)


def _bulk_jump_bastion_device_count(client, bulk_task_id: str | None, jump_label: str) -> int:
    if not client or not bulk_task_id or not jump_label:
        return 0
    try:
        raw = client.hget(_bulk_jump_bastion_counts_key(str(bulk_task_id)), str(jump_label))
        if raw is not None:
            return max(0, int(raw))
    except Exception:
        logger.exception("Falha ao ler contagem Redis do Jump Host %s no lote %s", jump_label, bulk_task_id)

    try:
        meta = _safe_get_task_meta(str(bulk_task_id))
        counts = meta.get("jump_bastion_device_counts") or {}
        if isinstance(counts, dict):
            return max(0, int(counts.get(str(jump_label)) or 0))
    except Exception:
        logger.exception("Falha ao ler contagem meta do Jump Host %s no lote %s", jump_label, bulk_task_id)
    return 0


def _record_jump_host_duration(lock_info: dict | None, duration_seconds: float | None, success: bool) -> None:
    if not success or not lock_info or not JUMP_HOST_WINDOW_ADAPTIVE_ENABLED:
        return
    jump_label = str((lock_info or {}).get("label") or "").strip()
    if not jump_label:
        return
    try:
        duration = float(duration_seconds or 0)
    except Exception:
        return
    if duration <= 0 or math.isnan(duration) or math.isinf(duration):
        return
    duration = min(duration, float(BACKUP_TASK_TIME_LIMIT_SECONDS))
    try:
        from app.services.realtime_backup_logs import get_redis_client

        client = get_redis_client()
        if not client:
            return
        avg_key = _jump_host_duration_avg_key()
        samples_key = _jump_host_duration_samples_key()
        previous_raw = client.hget(avg_key, jump_label)
        try:
            previous = float(previous_raw) if previous_raw is not None else None
        except Exception:
            previous = None
        if previous is None or previous <= 0:
            next_avg = duration
        else:
            alpha = max(0.01, min(1.0, JUMP_HOST_DURATION_EMA_ALPHA_PERCENT / 100.0))
            next_avg = (previous * (1.0 - alpha)) + (duration * alpha)
        pipe = client.pipeline()
        pipe.hset(avg_key, jump_label, round(next_avg, 3))
        pipe.hincrby(samples_key, jump_label, 1)
        pipe.expire(avg_key, JUMP_HOST_DURATION_AVG_TTL_SECONDS)
        pipe.expire(samples_key, JUMP_HOST_DURATION_AVG_TTL_SECONDS)
        pipe.execute()
    except Exception:
        logger.exception("Falha ao atualizar duração média do Jump Host %s", jump_label)


def _resolve_window_target_jump_host_slots(
    client,
    *,
    jump_label: str,
    current_slots: int,
    bulk_task_id: str | None,
) -> int:
    current = max(1, min(16, int(current_slots or 1)))
    if (
        not JUMP_HOST_WINDOW_ADAPTIVE_ENABLED
        or not client
        or not bulk_task_id
        or not jump_label
        or current <= 1
    ):
        return current

    device_count = _bulk_jump_bastion_device_count(client, bulk_task_id, jump_label)
    if device_count <= 0:
        return current

    try:
        avg_raw = client.hget(_jump_host_duration_avg_key(), jump_label)
        samples_raw = client.hget(_jump_host_duration_samples_key(), jump_label)
        avg_seconds = float(avg_raw) if avg_raw is not None else 0.0
        samples = int(samples_raw or 0)
    except Exception:
        logger.exception("Falha ao ler duração média do Jump Host %s", jump_label)
        return current

    if avg_seconds <= 0 or samples < JUMP_HOST_WINDOW_MIN_SAMPLES:
        return current

    target = int(math.ceil((float(device_count) * avg_seconds) / float(JUMP_HOST_WINDOW_SECONDS)))
    target = max(1, min(16, target))
    min_slots = max(1, min(current, JUMP_HOST_WINDOW_MIN_SLOTS))
    effective = max(min_slots, min(current, target))
    if effective != current:
        _emit_structured_event(
            "jump_host_window_slots_resolved",
            jump_host=jump_label,
            bulk_task_id=str(bulk_task_id),
            device_count=device_count,
            avg_duration_seconds=round(avg_seconds, 3),
            window_seconds=JUMP_HOST_WINDOW_SECONDS,
            previous_slots=current,
            new_slots=effective,
            min_slots=min_slots,
            samples=samples,
        )
    return effective


def _emit_structured_event(event_name: str, **payload) -> None:
    data = {"event": str(event_name or "unknown"), "ts": datetime.utcnow().isoformat() + "Z"}
    for key, value in (payload or {}).items():
        if value is None:
            continue
        data[str(key)] = value
    try:
        logger.info("backup_event %s", json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    except Exception:
        logger.exception("Falha ao emitir evento estruturado: %s", event_name)


def _parse_jump_host_slot_overrides() -> dict[str, int]:
    global _jump_host_slot_overrides_cache
    if _jump_host_slot_overrides_cache is not None:
        return _jump_host_slot_overrides_cache
    raw = str(os.getenv("JUMP_HOST_SLOTS_OVERRIDES", "") or "").strip()
    parsed: dict[str, int] = {}
    if not raw:
        _jump_host_slot_overrides_cache = parsed
        return parsed
    for chunk in raw.split(","):
        item = chunk.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        try:
            slots = int(value.strip())
        except Exception:
            continue
        parsed[key] = max(1, min(16, slots))
    _jump_host_slot_overrides_cache = parsed
    return parsed


def _resolve_effective_jump_host_slots(
    client,
    jump_label: str,
    base_slots: int,
    *,
    bulk_task_id: str | None = None,
) -> int:
    effective = max(1, int(base_slots or 1))
    overrides = _parse_jump_host_slot_overrides()
    if jump_label in overrides:
        effective = overrides[jump_label]
    elif "default" in overrides:
        effective = overrides["default"]

    if not JUMP_HOST_ADAPTIVE_ENABLED or not client:
        return max(1, min(16, effective))
    try:
        raw_dynamic = client.hget("backup_center:jump_host_adaptive_slots", jump_label)
        if raw_dynamic is not None:
            dynamic_slots = int(raw_dynamic)
            effective = max(1, min(16, dynamic_slots))
    except Exception:
        logger.exception("Falha ao ler slots adaptativos para jump host %s", jump_label)
    effective = max(1, min(16, effective))
    return _resolve_window_target_jump_host_slots(
        client,
        jump_label=str(jump_label or ""),
        current_slots=effective,
        bulk_task_id=bulk_task_id,
    )


def _message_indicates_jump_host_saturation(message: str | None) -> bool:
    text = str(message or "").strip().lower()
    if not text:
        return False
    # Falha do destino atras do bastion ou espera por slot nao significa que o
    # bastion saturou. Reduzir slots nesses casos cria uma espiral de lentidao.
    if any(
        marker in text
        for marker in (
            "timeout aguardando slot do jump host",
            "aguardando slot do jump host",
            "jump host respondeu mas o dispositivo destino",
            "rede inalcançável (jump_channel)",
            "rede inalcanavel (jump_channel)",
        )
    ):
        return False
    return any(
        marker in text
        for marker in (
            "error reading ssh protocol banner",
            "timeout opening channel",
            "channelexception",
            "no existing session",
            "sessao com jump host encerrada",
            "sessão com jump host encerrada",
            "banner exchange",
            "kex_exchange_identification",
        )
    )


def _message_indicates_severe_jump_host_saturation(message: str | None) -> bool:
    text = str(message or "").strip().lower()
    if not text:
        return False
    return any(
        marker in text
        for marker in (
            "sessao com jump host encerrada antes do shell ficar disponivel",
            "sessão com jump host encerrada antes do shell ficar disponivel",
            "nao foi possivel abrir shell interativo no jump host",
            "não foi possível abrir shell interativo no jump host",
            "error reading ssh protocol banner",
            "timeout opening channel",
            "kex_exchange_identification",
            "connection reset by peer",
        )
    )


def _is_nmcli_backend_unavailable_message(message: str | None) -> bool:
    text = str(message or "").strip().lower()
    if not text:
        return False
    markers = (
        "networkmanager indisponivel neste worker",
        "networkmanager indisponível neste worker",
        "backend do networkmanager indisponivel",
        "backend do networkmanager indisponível",
        "nmcli general status",
        "could not create nmclient object",
        "could not connect: no such file or directory",
        "nmcli nao encontrado",
        "nmcli não encontrado",
    )
    return any(marker in text for marker in markers)


def _is_transient_retry_denied_for_device(device_name: str | None = None, device_id: str | None = None) -> bool:
    if not TRANSIENT_RETRY_DENYLIST_DEVICE_NAMES and not TRANSIENT_RETRY_DENYLIST_DEVICE_IDS:
        return False
    normalized_name = _normalize_retry_token(device_name)
    normalized_id = _normalize_retry_token(device_id)
    if normalized_id and normalized_id in TRANSIENT_RETRY_DENYLIST_DEVICE_IDS:
        return True
    if normalized_name and normalized_name in TRANSIENT_RETRY_DENYLIST_DEVICE_NAMES:
        return True
    return False


def _should_retry_transient_failure(
    category: str | None,
    message: str | None,
    *,
    device_name: str | None = None,
    device_id: str | None = None,
) -> bool:
    normalized_category = str(category or "").strip().lower()
    if not normalized_category:
        return False

    from app.services.backup_diagnostics import is_transient_failure

    if not is_transient_failure(normalized_category):
        return False

    text = str(message or "").strip().lower()

    # Falha estrutural do worker VPN (nmcli/networkmanager ausente): nao adianta retentar.
    if _is_nmcli_backend_unavailable_message(text):
        return False

    # Quarentena de dispositivos cronicos para nao travar lotes com retentativas longas.
    if _is_transient_retry_denied_for_device(device_name=device_name, device_id=device_id):
        return False

    if normalized_category == "connection":
        hard_markers = (
            "connection refused",
            "no route to host",
            "network is unreachable",
            "unable to connect to remote host",
            "unable to connect to port",
            "timeout opening channel",
            "administratively prohibited",
            "jump host nao conseguiu abrir canal tcp",
            "jump host não conseguiu abrir canal tcp",
            "authentication failed",
            "invalid username",
            "invalid password",
            "unauthorized",
            "access denied",
            "permission denied",
            "wrong tcp port",
            "incorrect hostname",
        )
        if any(marker in text for marker in hard_markers):
            return False
    return True


def _bulk_followup_decision_key(bulk_task_id: str) -> str:
    return f"backup_center:bulk:transient_followup_decided:{bulk_task_id}"


def _bulk_followup_terminal_status(child_meta: dict) -> str:
    return str((child_meta or {}).get("status") or "").strip().lower()


def _bulk_child_task_is_terminal(child_id: str, child_meta: dict) -> bool:
    if bool((child_meta or {}).get("completed")):
        return True
    if _bulk_followup_terminal_status(child_meta) in {
        "success",
        "failed",
        "failure",
        "error",
        "stopped",
        "revoked",
        "completed",
    }:
        return True
    try:
        return str(celery_app.AsyncResult(child_id).state or "").upper() in {"SUCCESS", "FAILURE", "REVOKED"}
    except Exception:
        return False


def _bulk_child_result(child_id: str, child_meta: dict) -> dict:
    result = (child_meta or {}).get("result")
    if isinstance(result, dict):
        return result
    try:
        async_result = celery_app.AsyncResult(child_id)
        async_payload = async_result.result
        if isinstance(async_payload, dict):
            return async_payload
    except Exception:
        pass
    return {}


def _bulk_append_transient_candidate(
    candidate_ids: set[str],
    category_counter: Counter,
    *,
    device_id: str | None,
    device_name: str | None,
    category: str | None,
    message: str | None = None,
) -> None:
    normalized_category = str(category or "").strip().lower()
    normalized_device_id = str(device_id or "").strip()
    if not normalized_device_id or not normalized_category:
        return
    if not _should_retry_transient_failure(
        normalized_category,
        message,
        device_name=device_name,
        device_id=normalized_device_id,
    ):
        return
    candidate_ids.add(normalized_device_id)
    category_counter[normalized_category] += 1


def _collect_bulk_transient_followup_candidates(task_meta: dict) -> tuple[list[str], dict[str, int]]:
    from app.services.backup_diagnostics import classify_failure

    candidate_ids: set[str] = set()
    category_counter: Counter = Counter()
    for skipped_device_id in (task_meta or {}).get("skipped_jump_device_ids") or []:
        _bulk_append_transient_candidate(
            candidate_ids,
            category_counter,
            device_id=str(skipped_device_id),
            device_name=None,
            category="connection",
            message="Jump Host indisponivel no preflight do lote.",
        )

    child_task_ids = [str(tid) for tid in ((task_meta or {}).get("child_task_ids") or []) if tid]

    for child_id in child_task_ids:
        child_meta = _safe_get_task_meta(child_id)
        child_result = _bulk_child_result(child_id, child_meta)
        fallback_device_ids = [str(v) for v in ((child_meta or {}).get("device_ids") or []) if v]
        fallback_device_id = str((child_meta or {}).get("device_id") or "").strip() or None
        fallback_device_name = str((child_meta or {}).get("device_name") or "").strip() or None

        details = child_result.get("details") if isinstance(child_result, dict) else None
        if isinstance(details, list):
            for item in details:
                if not isinstance(item, dict) or bool(item.get("success")):
                    continue
                category = str(
                    item.get("failure_category")
                    or classify_failure(item.get("message") or "")
                ).strip().lower()
                device_id = str(item.get("device_id") or "").strip() or None
                device_name = str(item.get("device_name") or "").strip() or None
                _bulk_append_transient_candidate(
                    candidate_ids,
                    category_counter,
                    device_id=device_id,
                    device_name=device_name,
                    category=category,
                    message=item.get("message"),
                )
            continue

        if isinstance(child_result, dict) and ("success" in child_result or child_result.get("error")):
            child_success = bool(child_result.get("success"))
            if not child_success:
                category = str(
                    child_result.get("failure_category")
                    or classify_failure(
                        child_result.get("message")
                        or child_result.get("error")
                        or (child_meta or {}).get("message")
                        or (child_meta or {}).get("error")
                        or ""
                    )
                ).strip().lower()
                if fallback_device_id:
                    _bulk_append_transient_candidate(
                        candidate_ids,
                        category_counter,
                        device_id=fallback_device_id,
                        device_name=fallback_device_name,
                        category=category,
                        message=child_result.get("message") or child_result.get("error"),
                    )
                elif fallback_device_ids:
                    for device_id in fallback_device_ids:
                        _bulk_append_transient_candidate(
                            candidate_ids,
                            category_counter,
                            device_id=device_id,
                            device_name=fallback_device_name,
                            category=category,
                            message=child_result.get("message") or child_result.get("error"),
                        )

    return sorted(candidate_ids), {str(k): int(v) for k, v in category_counter.items()}


def _build_bulk_terminal_snapshot(task_meta: dict) -> tuple[bool, dict]:
    from app.services.backup_diagnostics import classify_failure

    bulk_meta = dict(task_meta or {})
    child_task_ids = [str(tid) for tid in (bulk_meta.get("child_task_ids") or []) if tid]
    total_tasks = max(int(bulk_meta.get("total_tasks") or 0), len(child_task_ids))
    if total_tasks <= 0:
        return False, {}
    if len(child_task_ids) < total_tasks:
        return False, {}

    child_task_device_count = {
        str(k): max(1, int(v))
        for k, v in (bulk_meta.get("child_task_device_count") or {}).items()
    }
    skipped_jump_unreachable = max(0, int(bulk_meta.get("skipped_jump_unreachable") or 0))
    done_tasks = 0
    success_tasks = 0
    failed_tasks = 0
    done_devices = skipped_jump_unreachable
    success_devices = 0
    failed_devices = skipped_jump_unreachable
    failure_category_counts: Counter = Counter()
    if skipped_jump_unreachable:
        failure_category_counts["connection"] += skipped_jump_unreachable

    for child_id in child_task_ids:
        child_meta = _safe_get_task_meta(child_id)
        if not _bulk_child_task_is_terminal(child_id, child_meta):
            return False, {}

        done_tasks += 1
        result = _bulk_child_result(child_id, child_meta)
        device_total = max(1, int(child_task_device_count.get(child_id, 1)))
        task_success_devices = 0
        task_failed_devices = 0
        task_success = True

        if isinstance(result, dict):
            details = result.get("details")
            if isinstance(details, list):
                if "total" in result or "success" in result or "failed" in result:
                    task_success_devices = max(0, int(result.get("success") or 0))
                    task_failed_devices = max(0, int(result.get("failed") or 0))
                for item in details:
                    if not isinstance(item, dict) or bool(item.get("success")):
                        continue
                    category = str(
                        item.get("failure_category")
                        or classify_failure(item.get("message") or "")
                    ).strip().lower() or "unknown"
                    failure_category_counts[category] += 1
                task_success = task_failed_devices == 0
            elif "success" in result:
                task_success = bool(result.get("success"))
                task_success_devices = 1 if task_success else 0
                task_failed_devices = 0 if task_success else 1
                if not task_success:
                    category = str(
                        result.get("failure_category")
                        or classify_failure(result.get("message") or "")
                    ).strip().lower() or "unknown"
                    failure_category_counts[category] += 1
            elif result.get("error"):
                task_success = False
                task_success_devices = 0
                task_failed_devices = device_total
                category = str(
                    classify_failure(result.get("error") or "")
                ).strip().lower() or "unknown"
                failure_category_counts[category] += max(1, device_total)
            else:
                task_success_devices = device_total
                task_failed_devices = 0
                task_success = True
        else:
            task_success_devices = device_total
            task_failed_devices = 0
            task_success = True

        if task_success_devices + task_failed_devices <= 0:
            task_success_devices = device_total if task_success else 0
            task_failed_devices = 0 if task_success else device_total
        elif (task_success_devices + task_failed_devices) < device_total:
            missing = device_total - (task_success_devices + task_failed_devices)
            if task_success:
                task_success_devices += missing
            else:
                task_failed_devices += missing

        done_devices += task_success_devices + task_failed_devices
        success_devices += task_success_devices
        failed_devices += task_failed_devices
        if task_success:
            success_tasks += 1
        else:
            failed_tasks += 1

    total_devices = int(bulk_meta.get("total_devices") or 0)
    total_devices = max(total_devices, done_devices, sum(child_task_device_count.get(tid, 1) for tid in child_task_ids))

    cancel_requested = bool(bulk_meta.get("cancel_requested"))
    if cancel_requested:
        status = "stopped"
        message = f"Interrompido. Sucesso: {success_devices} | Falhas: {failed_devices}"
    elif failed_devices > 0:
        status = "failed"
        message = f"Finalizado. Sucesso: {success_devices} | Falhas: {failed_devices}"
    else:
        status = "success"
        message = f"Finalizado. Sucesso: {success_devices} | Falhas: {failed_devices}"

    return True, {
        "status": status,
        "progress": 100,
        "completed": True,
        "completed_at": datetime.utcnow().isoformat() + "Z",
        "message": message,
        "total_tasks": total_tasks,
        "done_tasks": done_tasks,
        "success_tasks": success_tasks,
        "failed_tasks": failed_tasks,
        "running_tasks": 0,
        "queued_tasks": 0,
        "total_devices": total_devices,
        "done_devices": done_devices,
        "success_devices": success_devices,
        "failed_devices": failed_devices,
        "finished_task_ids": child_task_ids,
        "failure_category_counts": {str(k): int(v) for k, v in failure_category_counts.items()},
    }


def _normalize_auto_connection_type(raw_value: str | None) -> str:
    raw = str(raw_value or "").strip().lower()
    if raw in {"jump", "jump_host"}:
        return "jump_host"
    if raw in {"direct", "vpn"}:
        return raw
    return ""


def _truthy_auto(value) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "on", "yes", "sim"}


def _auto_device_subgroup_connection_type(device) -> str:
    subgroup = getattr(device, "subgroup", None)
    if subgroup and bool(getattr(subgroup, "is_active", True)):
        conn = _normalize_auto_connection_type(getattr(subgroup, "connection_type", None))
        if conn:
            return conn

    extra = dict(getattr(device, "extra_parameters", None) or {})
    conn = _normalize_auto_connection_type(
        extra.get("connection_subgroup_type") or extra.get("subgroup_connection_type")
    )
    enabled = _truthy_auto(
        extra.get("connection_subgroup_enabled")
        if "connection_subgroup_enabled" in extra
        else extra.get("subgroup_connection_enabled")
    )
    if conn and (enabled or "connection_subgroup_type" in extra or "subgroup_connection_type" in extra):
        return conn
    return ""


def _auto_resolve_enqueue_throttle(device):
    group = getattr(device, "group", None)
    if group and uses_jump_host(group, device=device) and getattr(group, "jump_host", None):
        host = str(getattr(group, "jump_host", "") or "").strip().lower()
        port = int(getattr(group, "jump_port", 22) or 22)
        return f"jump:{host}:{port}", AUTO_REPROCESS_JUMP_COUNTDOWN_STEP_SECONDS
    return "direct:global", 0


def _auto_next_countdown_for_device(device, throttle_counters):
    key, step_seconds = _auto_resolve_enqueue_throttle(device)
    slot = int(throttle_counters.get(key, 0))
    throttle_counters[key] = slot + 1
    if step_seconds > 0:
        return slot * step_seconds
    return slot // AUTO_REPROCESS_DIRECT_GLOBAL_BATCH_SIZE


def _auto_backup_queue_for_device(device) -> str:
    group = getattr(device, "group", None)
    if group and uses_vpn_tunnel(group, device=device):
        return "vpn_queue"
    return "celery"


def _resolve_device_vpn_requirement(device_id: str) -> tuple[bool, str | None]:
    """Retorna se o dispositivo exige VPN e o nome do grupo para mensagens operacionais."""
    from sqlalchemy.orm import joinedload
    from app.models.device import Device

    db = SessionLocal()
    try:
        device = db.query(Device).options(
            joinedload(Device.group),
            joinedload(Device.subgroup),
        ).filter_by(id=device_id).first()
        if not device or not device.group:
            return False, None
        return bool(uses_vpn_tunnel(device.group, device=device)), str(device.group.name or "")
    finally:
        db.close()


def _current_task_queue(task_request) -> str:
    try:
        delivery_info = getattr(task_request, "delivery_info", None) or {}
        return str(
            delivery_info.get("routing_key")
            or delivery_info.get("exchange")
            or delivery_info.get("queue")
            or ""
        ).strip()
    except Exception:
        return ""


def _bastion_key_for_group_fields(jump_host, jump_port) -> str:
    """Chave do bastion (jump_host:porta) usada para agrupar/limitar concorrencia."""
    host = str(jump_host or "").strip().lower()
    if not host:
        return "sem-bastion"
    try:
        port = int(jump_port or 22)
    except Exception:
        port = 22
    return f"{host}:{port}"


def _bastion_key_for_device(device) -> str:
    group = getattr(device, "group", None)
    if not group:
        return "sem-bastion"
    return _bastion_key_for_group_fields(
        getattr(group, "jump_host", None),
        getattr(group, "jump_port", 22),
    )


def _interleave_by_bastion(items, bastion_of, stagger_seconds: int = JUMP_BULK_BASTION_STAGGER_SECONDS):
    """Distribui os itens em round-robin entre bastions e calcula um countdown por bastion.

    - Round-robin: intercala bastions diferentes (item0=bastionA, item1=bastionB, ...),
      de forma que os primeiros workers livres peguem bastions distintos -> paralelismo
      maximo ENTRE bastions, sem contencao no slot de um unico bastion.
    - Stagger: o N-esimo dispositivo de um MESMO bastion recebe countdown N*stagger,
      espacando no tempo as sessoes que iriam para o mesmo destino.

    Retorna lista de tuplas (item, countdown_segundos) ja na ordem de enfileiramento.
    """
    from collections import OrderedDict

    buckets: "OrderedDict[str, list]" = OrderedDict()
    for it in items:
        buckets.setdefault(str(bastion_of(it)), []).append(it)

    ordered: list[tuple] = []
    counters: dict[str, int] = {}
    remaining = sum(len(v) for v in buckets.values())
    step = max(0, int(stagger_seconds or 0))
    while remaining > 0:
        for key, lst in buckets.items():
            if not lst:
                continue
            it = lst.pop(0)
            n = counters.get(key, 0)
            counters[key] = n + 1
            ordered.append((it, n * step))
            remaining -= 1
    return ordered


def _auto_append_group_phase_bucket(bucket: dict, device, *, force_vpn: bool = False):
    if not device or not getattr(device, "group_id", None):
        return
    group_key = str(device.group_id)
    entry = bucket.get(group_key)
    if not entry:
        entry = {
            "group_id": group_key,
            "group_name": (device.group.name if getattr(device, "group", None) else group_key),
            "device_ids": [],
            "force_vpn": False,
        }
        bucket[group_key] = entry
    entry["device_ids"].append(str(device.id))
    if force_vpn:
        entry["force_vpn"] = True


def _auto_finalize_group_phase_payload(bucket: dict):
    payload = []
    for _, entry in sorted(
        (bucket or {}).items(),
        key=lambda item: str((item[1] or {}).get("group_name") or "").lower(),
    ):
        device_ids = sorted(set((entry or {}).get("device_ids") or []))
        if not device_ids:
            continue
        payload.append(
            {
                "group_id": str((entry or {}).get("group_id") or "").strip(),
                "group_name": str((entry or {}).get("group_name") or "").strip(),
                "device_ids": device_ids,
                "force_vpn": bool((entry or {}).get("force_vpn")),
            }
        )
    return payload


def _auto_split_mass_backup_devices(devices, excluded_type_ids):
    allowed = []
    excluded = []
    for device in devices or []:
        if getattr(device, "device_type_id", None) in excluded_type_ids:
            excluded.append(device)
            continue
        allowed.append(device)
    return allowed, excluded


def _auto_device_jump_endpoint(device):
    group = getattr(device, "group", None)
    if not group or not uses_jump_host(group, device=device):
        return "", "", 0
    host = str(getattr(group, "jump_host", "") or "").strip()
    try:
        port = int(getattr(group, "jump_port", 22) or 22)
    except Exception:
        port = 22
    key = f"{host}:{port}" if host else f"missing:{str(getattr(group, 'id', 'unknown'))}"
    return key, host, port


def _auto_bulk_preflight_jump_hosts(devices, tenant_id: str):
    from app.services.network_precheck import run_network_precheck

    enabled = _env_bool("BULK_PREFLIGHT_JUMP_ENABLED", "1")
    if not enabled:
        return list(devices or []), {
            "enabled": False,
            "checked_endpoints": 0,
            "total_endpoints": 0,
            "probe_truncated": False,
            "skipped_jump_unreachable": 0,
            "skipped_device_ids": [],
            "unreachable_endpoints": [],
        }

    timeout_seconds = _env_int("BULK_PREFLIGHT_JUMP_TIMEOUT_SECONDS", 3, minimum=1, maximum=15)
    skip_unreachable = _env_bool("BULK_PREFLIGHT_SKIP_UNREACHABLE", "1")
    max_endpoints = _env_int("BULK_PREFLIGHT_JUMP_MAX_ENDPOINTS", 30, minimum=1, maximum=500)

    endpoint_map = {}
    for device in devices or []:
        key, host, port = _auto_device_jump_endpoint(device)
        if not key:
            continue
        entry = endpoint_map.get(key)
        if not entry:
            group_name = str(getattr(getattr(device, "group", None), "name", "") or "").strip() or "Sem grupo"
            entry = {
                "endpoint": f"{host}:{port}" if host else "jump_host_sem_config",
                "host": host,
                "port": int(port),
                "devices": [],
                "group_names": {group_name},
            }
            endpoint_map[key] = entry
        entry["devices"].append(device)
        entry["group_names"].add(
            str(getattr(getattr(device, "group", None), "name", "") or "").strip() or "Sem grupo"
        )

    if not endpoint_map:
        return list(devices or []), {
            "enabled": True,
            "checked_endpoints": 0,
            "total_endpoints": 0,
            "probe_truncated": False,
            "skipped_jump_unreachable": 0,
            "skipped_device_ids": [],
            "unreachable_endpoints": [],
        }

    ordered_keys = sorted(
        endpoint_map.keys(),
        key=lambda item: len(endpoint_map[item]["devices"]),
        reverse=True,
    )
    probe_keys = ordered_keys[:max_endpoints]
    probe_truncated = len(probe_keys) < len(ordered_keys)
    endpoint_result = {}
    unreachable_endpoints = []

    for key in probe_keys:
        entry = endpoint_map[key]
        host = str(entry.get("host") or "").strip()
        port = int(entry.get("port") or 22)

        if not host:
            endpoint_result[key] = {"tcp_ok": False, "tcp_method": "missing_jump_host"}
            unreachable_endpoints.append(
                {
                    "endpoint": str(entry.get("endpoint") or "jump_host_sem_config"),
                    "devices": len(entry.get("devices") or []),
                    "groups": sorted(entry.get("group_names") or []),
                    "tcp_method": "missing_jump_host",
                }
            )
            continue

        try:
            precheck = run_network_precheck(
                host=host,
                port=port,
                timeout_seconds=timeout_seconds,
                jump_host=None,
            )
            tcp_ok = bool(getattr(precheck, "tcp_ok", False))
            tcp_method = str(getattr(precheck, "tcp_method", "") or "direct")
        except Exception:
            tcp_ok = False
            tcp_method = "exception"

        endpoint_result[key] = {"tcp_ok": tcp_ok, "tcp_method": tcp_method}
        if not tcp_ok:
            unreachable_endpoints.append(
                {
                    "endpoint": str(entry.get("endpoint") or f"{host}:{port}"),
                    "devices": len(entry.get("devices") or []),
                    "groups": sorted(entry.get("group_names") or []),
                    "tcp_method": tcp_method,
                }
            )

    for key in ordered_keys[len(probe_keys):]:
        endpoint_result[key] = {"tcp_ok": True, "tcp_method": "skipped_limit"}

    allowed = []
    skipped = []
    for device in devices or []:
        key, _host, _port = _auto_device_jump_endpoint(device)
        if not key:
            allowed.append(device)
            continue
        result = endpoint_result.get(key) or {}
        tcp_ok = bool(result.get("tcp_ok", True))
        if (not tcp_ok) and skip_unreachable:
            skipped.append(device)
            continue
        allowed.append(device)

    return allowed, {
        "enabled": True,
        "checked_endpoints": len(probe_keys),
        "total_endpoints": len(ordered_keys),
        "probe_truncated": bool(probe_truncated),
        "skipped_jump_unreachable": len(skipped),
        "skipped_device_ids": [str(getattr(device, "id", "")) for device in skipped if getattr(device, "id", None)],
        "unreachable_endpoints": unreachable_endpoints,
    }


def _safe_get_task_meta(task_id: str) -> dict:
    from app.services.realtime_backup_logs import get_task_meta

    try:
        return get_task_meta(str(task_id)) or {}
    except Exception:
        logger.exception("Falha ao ler task meta %s", task_id)
        return {}


def _maybe_finalize_bulk_and_schedule_followup(bulk_task_id: str | None) -> None:
    from app.services.realtime_backup_logs import append_task_log, get_redis_client, update_task_meta

    if not bulk_task_id:
        return

    bulk_meta = _safe_get_task_meta(str(bulk_task_id))
    if not bulk_meta or not bool(bulk_meta.get("is_bulk")):
        return

    ready, snapshot = _build_bulk_terminal_snapshot(bulk_meta)
    if not ready:
        return

    if not bool(bulk_meta.get("completed")):
        update_task_meta(str(bulk_task_id), **snapshot)
        bulk_meta = _safe_get_task_meta(str(bulk_task_id))
        if bulk_meta:
            bulk_meta.update(snapshot)
    else:
        bulk_meta.update(snapshot)

    operation_kind = str(bulk_meta.get("operation_kind") or "").strip().lower()
    if operation_kind != "backup_bulk":
        return
    if not BULK_TRANSIENT_FOLLOWUP_ENABLED or bool(bulk_meta.get("cancel_requested")):
        return

    client = get_redis_client()
    decision_key = _bulk_followup_decision_key(str(bulk_task_id))
    if client:
        try:
            if not client.set(decision_key, "1", nx=True, ex=60 * 60 * 24 * 30):
                return
        except Exception:
            logger.exception("Falha ao registrar decisao de follow-up do lote %s", bulk_task_id)
            if bulk_meta.get("transient_followup_decided"):
                return
    elif bulk_meta.get("transient_followup_decided"):
        return

    candidate_ids, category_counts = _collect_bulk_transient_followup_candidates(bulk_meta)
    tenant_id = str(bulk_meta.get("tenant_id") or "").strip()
    category_counts = {str(k): int(v) for k, v in (category_counts or {}).items()}

    if not candidate_ids or not tenant_id:
        update_task_meta(
            str(bulk_task_id),
            transient_followup_decided=True,
            transient_followup_status="not_needed",
            transient_followup_candidate_count=0,
            transient_followup_categories=category_counts,
        )
        append_task_log(
            str(bulk_task_id),
            "Backup em massa",
            "Lote concluido sem candidatos de falha transitoria para reprocessamento automatico.",
            "info",
        )
        return

    followup_task_id = f"bulk-followup-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{os.urandom(3).hex()}"
    run_bulk_transient_followup_task.apply_async(
        args=[tenant_id, candidate_ids, str(bulk_task_id)],
        countdown=BULK_TRANSIENT_FOLLOWUP_DELAY_SECONDS,
        queue="celery",
        task_id=followup_task_id,
    )
    update_task_meta(
        str(bulk_task_id),
        transient_followup_decided=True,
        transient_followup_status="scheduled",
        transient_followup_task_id=followup_task_id,
        transient_followup_candidate_count=len(candidate_ids),
        transient_followup_categories=category_counts,
        transient_followup_delay_seconds=BULK_TRANSIENT_FOLLOWUP_DELAY_SECONDS,
        transient_followup_scheduled_at=datetime.utcnow().isoformat() + "Z",
    )
    category_text = ", ".join(f"{k}={v}" for k, v in sorted(category_counts.items()))
    append_task_log(
        str(bulk_task_id),
        "Backup em massa",
        (
            f"{len(candidate_ids)} dispositivo(s) com falha transitoria "
            f"serao reprocessados automaticamente em {BULK_TRANSIENT_FOLLOWUP_DELAY_SECONDS // 60} min. "
            f"Categorias: {category_text or 'n/a'}. Task: {followup_task_id}"
        ),
        "warning",
    )


def _adapt_jump_host_slots(lock_info: dict | None, success: bool, message: str | None) -> None:
    if not lock_info or not JUMP_HOST_ADAPTIVE_ENABLED:
        return
    jump_label = str(lock_info.get("label") or "").strip()
    if not jump_label:
        return
    base_slots = max(1, int(lock_info.get("base_slots") or lock_info.get("max_slots") or 1))

    from app.services.realtime_backup_logs import get_redis_client

    client = get_redis_client()
    if not client:
        return

    slots_hash = "backup_center:jump_host_adaptive_slots"
    fail_streak_key = f"backup_center:jump_host_adaptive:fail:{jump_label}"
    success_streak_key = f"backup_center:jump_host_adaptive:success:{jump_label}"
    cooldown_key = f"backup_center:jump_host_adaptive:cooldown:{jump_label}"
    allowed_max_slots = max(1, min(16, base_slots + JUMP_HOST_ADAPTIVE_MAX_BOOST))
    current_slots = _resolve_effective_jump_host_slots(client, jump_label, base_slots)

    # Do not churn slot limits while in cooldown.
    try:
        if client.get(cooldown_key):
            return
    except Exception:
        return

    if success:
        try:
            success_streak = int(client.incr(success_streak_key))
            client.expire(success_streak_key, JUMP_HOST_ADAPTIVE_STREAK_TTL_SECONDS)
            client.delete(fail_streak_key)
            if success_streak >= JUMP_HOST_ADAPTIVE_SUCCESS_STREAK and current_slots < allowed_max_slots:
                next_slots = min(allowed_max_slots, current_slots + 1)
                client.hset(slots_hash, jump_label, next_slots)
                client.setex(cooldown_key, JUMP_HOST_ADAPTIVE_COOLDOWN_SECONDS, "1")
                client.delete(success_streak_key)
                inc_counter(
                    "jump_host_adaptive_slot_changes_total",
                    labels={"jump_host": jump_label, "direction": "up"},
                )
                _emit_structured_event(
                    "jump_host_slots_changed",
                    jump_host=jump_label,
                    direction="up",
                    previous_slots=current_slots,
                    new_slots=next_slots,
                    reason="success_streak",
                )
        except Exception:
            logger.exception("Falha ao ajustar slots adaptativos (success) para %s", jump_label)
        return

    if not _message_indicates_jump_host_saturation(message):
        return
    try:
        fail_streak = int(client.incr(fail_streak_key))
        client.expire(fail_streak_key, JUMP_HOST_ADAPTIVE_STREAK_TTL_SECONDS)
        client.delete(success_streak_key)
        severe_saturation = _message_indicates_severe_jump_host_saturation(message)
        severe_threshold_reached = fail_streak >= JUMP_HOST_ADAPTIVE_SEVERE_FAIL_STREAK
        regular_threshold_reached = fail_streak >= JUMP_HOST_ADAPTIVE_FAIL_STREAK
        if current_slots > 1 and (regular_threshold_reached or (severe_saturation and severe_threshold_reached)):
            if severe_saturation and severe_threshold_reached:
                next_slots = 1 if JUMP_HOST_ADAPTIVE_SEVERE_DROP_TO_ONE else max(1, current_slots - 2)
                cooldown_seconds = JUMP_HOST_ADAPTIVE_SEVERE_COOLDOWN_SECONDS
                reason = "severe_saturation_streak"
            else:
                next_slots = max(1, current_slots - 1)
                cooldown_seconds = JUMP_HOST_ADAPTIVE_COOLDOWN_SECONDS
                reason = "saturation_streak"
            client.hset(slots_hash, jump_label, next_slots)
            client.setex(cooldown_key, cooldown_seconds, "1")
            client.delete(fail_streak_key)
            inc_counter(
                "jump_host_adaptive_slot_changes_total",
                labels={"jump_host": jump_label, "direction": "down"},
            )
            _emit_structured_event(
                "jump_host_slots_changed",
                jump_host=jump_label,
                direction="down",
                previous_slots=current_slots,
                new_slots=next_slots,
                reason=reason,
            )
    except Exception:
        logger.exception("Falha ao ajustar slots adaptativos (failure) para %s", jump_label)


def _record_jump_host_outcome(jump_label: str, success: bool) -> None:
    """Registra resultado (sucesso/falha) na janela deslizante do circuit breaker."""
    if not jump_label:
        return
    try:
        from app.services.realtime_backup_logs import get_redis_client
        client = get_redis_client()
        if not client:
            return
        now_ms = int(time.monotonic() * 1000)
        key = f"backup_center:cb:outcomes:{jump_label}"
        entry = f"{1 if success else 0}:{now_ms}"
        client.rpush(key, entry)
        client.expire(key, CIRCUIT_BREAKER_WINDOW_SECONDS + 60)
    except Exception:
        logger.exception("Falha ao registrar outcome do circuit breaker para %s", jump_label)


def _check_jump_host_circuit_breaker(jump_label: str) -> tuple[bool, str, int]:
    """Verifica se o circuit breaker do jump host está aberto.
    Retorna (is_open, reason, retry_after_seconds).
    """
    if not jump_label:
        return False, "", 0
    try:
        from app.services.realtime_backup_logs import get_redis_client
        client = get_redis_client()
        if not client:
            return False, "", 0

        open_key = f"backup_center:cb:open:{jump_label}"
        if client.get(open_key):
            ttl = max(0, int(client.ttl(open_key) or 0))
            return True, (
                f"Circuit breaker ABERTO para Jump Host {jump_label}. "
                f"Aguardando {ttl}s antes de novas tentativas."
            ), ttl

        outcomes_key = f"backup_center:cb:outcomes:{jump_label}"
        entries = client.lrange(outcomes_key, 0, -1)
        if not entries:
            return False, "", 0

        now_ms = int(time.monotonic() * 1000)
        cutoff_ms = now_ms - (CIRCUIT_BREAKER_WINDOW_SECONDS * 1000)
        successes = 0
        failures = 0
        valid_entries = []
        for raw in entries:
            try:
                parts = str(raw).split(":")
                outcome = int(parts[0])
                ts = int(parts[1])
                if ts >= cutoff_ms:
                    valid_entries.append(raw)
                    if outcome == 1:
                        successes += 1
                    else:
                        failures += 1
            except Exception:
                continue

        # Limpa entradas expiradas
        if len(valid_entries) < len(entries):
            try:
                pipe = client.pipeline()
                pipe.delete(outcomes_key)
                if valid_entries:
                    pipe.rpush(outcomes_key, *valid_entries)
                    pipe.expire(outcomes_key, CIRCUIT_BREAKER_WINDOW_SECONDS + 60)
                pipe.execute()
            except Exception:
                pass

        total = successes + failures
        if total < CIRCUIT_BREAKER_MIN_SAMPLES:
            return False, "", 0

        fail_pct = int((failures / total) * 100)
        if fail_pct >= CIRCUIT_BREAKER_THRESHOLD_PERCENT:
            client.setex(open_key, CIRCUIT_BREAKER_OPEN_SECONDS, "1")
            inc_counter(
                "jump_host_circuit_breaker_opened_total",
                labels={"jump_host": jump_label},
            )
            _emit_structured_event(
                "circuit_breaker_opened",
                jump_host=jump_label,
                fail_pct=fail_pct,
                total_samples=total,
                failures=failures,
                window_seconds=CIRCUIT_BREAKER_WINDOW_SECONDS,
                open_seconds=CIRCUIT_BREAKER_OPEN_SECONDS,
            )
            return True, (
                f"Circuit breaker ATIVADO para Jump Host {jump_label}: "
                f"{fail_pct}% de falhas ({failures}/{total}) na janela de {CIRCUIT_BREAKER_WINDOW_SECONDS}s. "
                f"Bloqueado por {CIRCUIT_BREAKER_OPEN_SECONDS}s."
            ), int(CIRCUIT_BREAKER_OPEN_SECONDS)
        return False, "", 0
    except Exception:
        logger.exception("Falha ao verificar circuit breaker para %s", jump_label)
        return False, "", 0


def _resolve_device_observability_context(device_id: str) -> dict:
    from app.models.device import Device
    from app.models.device_type import DeviceType

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return {
                "device_id": str(device_id),
                "device_name": "unknown",
                "tenant_id": "unknown",
                "device_type": "unknown",
                "script_name": "unknown",
                "group_name": "unknown",
                "target_host": "unknown",
                "target_port": "0",
                "jump_host": "direct",
            }
        device_type_name = "unknown"
        script_name = "unknown"
        if getattr(device, "device_type_id", None):
            row = db.query(DeviceType.name, DeviceType.script_name).filter(DeviceType.id == device.device_type_id).first()
            if row:
                if row[0]:
                    device_type_name = str(row[0]).strip() or "unknown"
                if row[1]:
                    script_name = str(row[1]).strip() or "unknown"
        jump_host_label = "direct"
        group = getattr(device, "group", None)
        group_name = str(getattr(group, "name", "") or "Sem grupo")
        if group and uses_jump_host(group, device=device) and getattr(group, "jump_host", None):
            jump_host_label = f"{group.jump_host}:{int(getattr(group, 'jump_port', 22) or 22)}"
        return {
            "device_id": str(device_id),
            "device_name": str(getattr(device, "name", "") or ""),
            "tenant_id": str(getattr(device, "tenant_id", "unknown") or "unknown"),
            "device_type": device_type_name,
            "script_name": script_name,
            "group_name": group_name,
            "target_host": str(getattr(device, "ip_address", "") or ""),
            "target_port": str(int(getattr(device, "port", 22) or 22)),
            "jump_host": jump_host_label,
        }
    except Exception:
        logger.exception("Falha ao resolver contexto de observabilidade para %s", device_id)
        return {
            "device_id": str(device_id),
            "device_name": "unknown",
            "tenant_id": "unknown",
            "device_type": "unknown",
            "script_name": "unknown",
            "group_name": "unknown",
            "target_host": "unknown",
            "target_port": "0",
            "jump_host": "unknown",
        }
    finally:
        db.close()


def _validate_device_execution_allowed(device_id: str) -> tuple[bool, str | None, str | None]:
    """
    Garante que o dispositivo pode executar backup.
    Regras:
    - Dispositivo deve existir e estar ativo.
    - Se possuir grupo, o grupo precisa estar ativo.
    """
    from app.models.device import Device

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return False, "Dispositivo nao encontrado.", "device_not_found"
        if not bool(getattr(device, "is_active", True)):
            return False, "Dispositivo inativo. Backup bloqueado.", "device_inactive"
        group = getattr(device, "group", None)
        if group is not None and not bool(getattr(group, "is_active", True)):
            group_name = str(getattr(group, "name", "") or "Sem grupo")
            return (
                False,
                f'Grupo "{group_name}" esta inativo. Backup bloqueado.',
                "group_inactive",
            )
        return True, None, None
    except Exception:
        logger.exception("Falha ao validar elegibilidade de execucao para %s", device_id)
        return False, "Falha ao validar estado do dispositivo/grupo.", "validation_error"
    finally:
        db.close()


def _normalize_host(value: str | None) -> str:
    return str(value or "").strip().lower()


def _resolve_jump_host_lock(device_id: str) -> dict | None:
    from app.models.device import Device

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device or not device.group or not uses_jump_host(device.group, device=device):
            return None

        jump_host = str(getattr(device.group, "jump_host", "") or "").strip()
        if not jump_host:
            return None

        jump_port = int(getattr(device.group, "jump_port", 22) or 22)
        target_host = _normalize_host(getattr(device, "ip_address", None))
        jump_host_normalized = _normalize_host(jump_host)
        if target_host and target_host == jump_host_normalized:
            return None

        group_name = str(getattr(device.group, "name", "") or "Sem grupo").strip()
        return {
            "base_key": f"backup_center:jump_host_lock:{jump_host_normalized}:{jump_port}",
            "label": f"{jump_host}:{jump_port}",
            "group_name": group_name,
            "base_slots": JUMP_HOST_MAX_SLOTS,
            "max_slots": JUMP_HOST_MAX_SLOTS,
        }
    except Exception:
        logger.exception("Falha ao resolver lock de Jump Host para %s", device_id)
        return None
    finally:
        db.close()


@contextmanager
def _jump_host_lock_context(device_id: str, task_id: str | None = None, bulk_task_id: str | None = None):
    from app.services.realtime_backup_logs import append_task_log, get_redis_client

    lock_info = _resolve_jump_host_lock(device_id)
    if not lock_info:
        yield None
        return

    client = get_redis_client()
    if not client:
        logger.warning(
            "Redis indisponivel; seguindo sem lock de Jump Host para %s (%s).",
            device_id,
            lock_info["label"],
        )
        yield {**lock_info, "max_slots": lock_info.get("base_slots") or 1}
        return

    base_slots = max(1, int(lock_info.get("base_slots") or lock_info.get("max_slots") or 1))
    max_slots = _resolve_effective_jump_host_slots(
        client,
        str(lock_info.get("label") or ""),
        base_slots,
        bulk_task_id=bulk_task_id,
    )
    slot_locks = [
        client.lock(
            f"{lock_info['base_key']}:slot:{idx}",
            timeout=JUMP_HOST_LOCK_TIMEOUT_SECONDS,
            blocking_timeout=1,
            sleep=1.0,
        )
        for idx in range(max_slots)
    ]
    waiting_logged = False
    acquired_lock = None
    acquired_slot = None
    effective_wait_seconds = _effective_jump_host_wait_seconds(bulk_task_id)

    wait_started_at = time.monotonic()
    try:
        while True:
            if _should_stop_now(bulk_task_id):
                wait_elapsed = max(0.0, time.monotonic() - wait_started_at)
                observe_histogram(
                    "jump_host_wait_seconds",
                    wait_elapsed,
                    labels={"jump_host": lock_info["label"], "result": "cancelled"},
                )
                inc_counter(
                    "jump_host_slot_acquire_total",
                    labels={"jump_host": lock_info["label"], "result": "cancelled", "slots": str(max_slots)},
                )
                raise JumpHostSlotCancelledError(
                    f"Execucao interrompida enquanto aguardava slot do Jump Host {lock_info['label']}."
                )
            if (time.monotonic() - wait_started_at) >= effective_wait_seconds:
                wait_elapsed = max(0.0, time.monotonic() - wait_started_at)
                observe_histogram(
                    "jump_host_wait_seconds",
                    wait_elapsed,
                    labels={"jump_host": lock_info["label"], "result": "timeout"},
                )
                inc_counter(
                    "jump_host_slot_acquire_total",
                    labels={"jump_host": lock_info["label"], "result": "timeout", "slots": str(max_slots)},
                )
                raise JumpHostSlotTimeoutError(
                    (
                        f"Timeout aguardando slot do Jump Host {lock_info['label']} "
                        f"(limite {max_slots} conexoes simultaneas) "
                        f"apos {effective_wait_seconds}s."
                    )
                )

            for slot_idx, slot_lock in enumerate(slot_locks, start=1):
                try:
                    if slot_lock.acquire(blocking=False):
                        acquired_lock = slot_lock
                        acquired_slot = slot_idx
                        break
                except Exception:
                    logger.exception(
                        "Falha ao tentar adquirir slot %s do Jump Host %s",
                        slot_idx,
                        lock_info["label"],
                    )

            if acquired_lock is not None:
                wait_elapsed = max(0.0, time.monotonic() - wait_started_at)
                observe_histogram(
                    "jump_host_wait_seconds",
                    wait_elapsed,
                    labels={"jump_host": lock_info["label"], "result": "acquired"},
                )
                inc_counter(
                    "jump_host_slot_acquire_total",
                    labels={"jump_host": lock_info["label"], "result": "acquired", "slots": str(max_slots)},
                )
                if waiting_logged:
                    append_task_log(
                        task_id,
                        "Sistema",
                        (
                            f"Slot {acquired_slot}/{max_slots} liberado no Jump Host {lock_info['label']}. "
                            "Prosseguindo com o backup."
                        ),
                        "info",
                    )
                yield {**lock_info, "slot": acquired_slot, "max_slots": max_slots, "base_slots": base_slots}
                return

            if not waiting_logged:
                append_task_log(
                    task_id,
                    "Sistema",
                    (
                        f"Jump Host compartilhado detectado ({lock_info['label']}). "
                        f"Aguardando slot livre (max {max_slots} conexoes simultaneas) para evitar excesso de canais SSH."
                    ),
                    "info",
                )
                waiting_logged = True

            if _sleep_with_stop_poll(1, bulk_task_id):
                wait_elapsed = max(0.0, time.monotonic() - wait_started_at)
                observe_histogram(
                    "jump_host_wait_seconds",
                    wait_elapsed,
                    labels={"jump_host": lock_info["label"], "result": "cancelled"},
                )
                inc_counter(
                    "jump_host_slot_acquire_total",
                    labels={"jump_host": lock_info["label"], "result": "cancelled", "slots": str(max_slots)},
                )
                raise JumpHostSlotCancelledError(
                    f"Execucao interrompida enquanto aguardava slot do Jump Host {lock_info['label']}."
                )
    finally:
        try:
            if acquired_lock and acquired_lock.owned():
                acquired_lock.release()
        except Exception:
            logger.exception("Falha ao liberar lock de Jump Host %s", lock_info["label"])


def _multi_device_progress(total_devices: int, processed_devices: int, current_fraction: float = 0.0) -> int:
    total = max(1, int(total_devices or 1))
    processed = max(0.0, float(processed_devices or 0))
    fraction = max(0.0, min(0.99, float(current_fraction or 0.0)))
    # Reserva 5% para bootstrap e 5% para finalizacao.
    return min(95, max(5, int(5 + (((processed + fraction) / total) * 90))))


from celery.exceptions import SoftTimeLimitExceeded

@celery_app.task(
    bind=True,
    max_retries=1,
    time_limit=BACKUP_TASK_TIME_LIMIT_SECONDS,
    soft_time_limit=BACKUP_TASK_SOFT_TIME_LIMIT_SECONDS,
)
def run_backup_task(self, device_id: str, bulk_task_id: str = None):
    """
    Task assíncrona wrapper com Time Limit rigoroso.
    """
    try:
        return _internal_run_backup_task(self, device_id, bulk_task_id)
    except SoftTimeLimitExceeded:
        import logging
        from app.services.realtime_backup_logs import append_task_log, update_task_meta
        from app.models.backup import Backup, BackupStatus
        from app.models.device import Device
        from app.core.database import SessionLocal
        import datetime as _dt
        _stl_logger = logging.getLogger(__name__)
        _stl_logger.error(f"[Device {device_id}] Celery Time Limit excedido (sessão congelada).")
        error_msg = f"Falha durante o backup. Detalhe: SoftTimeLimitExceeded()"
        update_task_meta(
            self.request.id,
            status="failed",
            message=(
                "Timeout absoluto de socket/Worker atingido "
                f"({BACKUP_TASK_SOFT_TIME_LIMIT_SECONDS}s)."
            ),
            completed=True,
            error="SoftTimeLimitExceeded."
        )
        append_task_log(self.request.id, device_id, "Processo interrompido à força pelo limite de tempo do sistema. Possível timeout silencioso no equipamento originado.", "error")
        # Persiste o registro de falha no banco para que o dispositivo tenha evidência do erro.
        try:
            _db = SessionLocal()
            try:
                _now = _dt.datetime.utcnow()
                _device_row = _db.query(Device).filter_by(id=device_id).first()
                if _device_row:
                    _backup = Backup(
                        device_id=_device_row.id,
                        status=BackupStatus.FAILED,
                        error_message=error_msg,
                        started_at=_now,
                        completed_at=_now,
                        duration_seconds=BACKUP_TASK_SOFT_TIME_LIMIT_SECONDS,
                    )
                    _db.add(_backup)
                    _device_row.last_backup_at = _now
                    _device_row.last_backup_status = "failure"
                    _extra = dict(_device_row.extra_parameters or {})
                    _extra["last_backup_failure_category"] = "timeout"
                    _extra["last_backup_failure_label"] = "Timeout absoluto (Celery)"
                    _extra["last_backup_failure_message"] = error_msg
                    _extra["last_backup_failure_at"] = _now.isoformat() + "Z"
                    _device_row.extra_parameters = _extra
                    _db.commit()
            finally:
                _db.close()
        except Exception:
            _stl_logger.exception("Falha ao persistir resultado de SoftTimeLimitExceeded para device %s", device_id)
        return {
            "success": False,
            "error": f"Timeout absoluto ({BACKUP_TASK_SOFT_TIME_LIMIT_SECONDS}s) atingido.",
        }

def _internal_run_backup_task(self, device_id: str, bulk_task_id: str = None):
    """
    Task assíncrona para executar backup de um dispositivo.
    
    Args:
        device_id: UUID do dispositivo
    
    Returns:
        Dict com resultado do backup
    """
    from app.services.backup_executor import backup_executor
    from app.services.realtime_backup_logs import append_task_log, update_task_meta
    from app.services.backup_diagnostics import classify_failure

    task_id = self.request.id
    started_at = time.monotonic()
    observability_ctx = _resolve_device_observability_context(device_id)
    device_name_hint = str(observability_ctx.get("device_name") or "").strip()
    base_metric_labels = {
        "tenant_id": str(observability_ctx.get("tenant_id") or "unknown"),
        "device_type": str(observability_ctx.get("device_type") or "unknown"),
        "script_name": str(observability_ctx.get("script_name") or "unknown"),
        "group_name": str(observability_ctx.get("group_name") or "unknown"),
        "target_host": str(observability_ctx.get("target_host") or "unknown"),
        "target_port": str(observability_ctx.get("target_port") or "0"),
        "jump_host": str(observability_ctx.get("jump_host") or "unknown"),
    }
    attempt_no = int(self.request.retries or 0) + 1
    lock_info = None
    backup_exec_started_at = None
    backup_exec_duration_seconds = None

    def _track_attempt_outcome(outcome: str, category: str, message: str | None, *, retry_scheduled: bool = False) -> None:
        duration = max(0.0, time.monotonic() - started_at)
        metric_labels = {
            **base_metric_labels,
            "outcome": str(outcome or "unknown"),
            "category": str(category or "none"),
        }
        observe_histogram("backup_task_duration_seconds", duration, labels=metric_labels)
        inc_counter("backup_task_total", labels=metric_labels)
        if retry_scheduled:
            inc_counter(
                "backup_retry_total",
                labels={
                    **base_metric_labels,
                    "category": str(category or "none"),
                    "reason": str(outcome or "retry"),
                },
            )
        _emit_structured_event(
            "backup_task_attempt_finished",
            task_id=str(task_id),
            bulk_task_id=str(bulk_task_id) if bulk_task_id else None,
            device_id=str(device_id),
            tenant_id=base_metric_labels["tenant_id"],
            device_type=base_metric_labels["device_type"],
            script_name=base_metric_labels["script_name"],
            attempt=attempt_no,
            outcome=str(outcome or "unknown"),
            category=str(category or "none"),
            duration_ms=int(duration * 1000),
            retries_done=int(self.request.retries or 0),
            max_retries=int(self.max_retries or 0),
            jump_host=base_metric_labels["jump_host"],
            group_name=base_metric_labels["group_name"],
            target_host=base_metric_labels["target_host"],
            target_port=base_metric_labels["target_port"],
            message=(str(message or "")[:500] or None),
        )
        _touch_bulk_activity(bulk_task_id)

    _emit_structured_event(
        "backup_task_attempt_started",
        task_id=str(task_id),
        bulk_task_id=str(bulk_task_id) if bulk_task_id else None,
        device_id=str(device_id),
        tenant_id=base_metric_labels["tenant_id"],
        device_type=base_metric_labels["device_type"],
        script_name=base_metric_labels["script_name"],
        attempt=attempt_no,
        retries_done=int(self.request.retries or 0),
        max_retries=int(self.max_retries or 0),
        jump_host=base_metric_labels["jump_host"],
        group_name=base_metric_labels["group_name"],
        target_host=base_metric_labels["target_host"],
        target_port=base_metric_labels["target_port"],
    )

    try:
        _touch_bulk_activity(bulk_task_id)
        if _should_stop_now(bulk_task_id):
            cancelled_result = {
                'device_id': device_id,
                'success': False,
                'message': 'Backup interrompido pelo operador (parada forçada).'
            }
            update_task_meta(
                task_id,
                status="stopped",
                progress=100,
                message="Execucao interrompida por parada forçada.",
                completed=True,
                result=cancelled_result,
            )
            append_task_log(task_id, "Sistema", "Task interrompida por parada forçada.", "warning")
            _track_attempt_outcome(
                outcome="stopped",
                category="cancelled",
                message=cancelled_result["message"],
            )
            return cancelled_result

        allowed, block_message, block_category = _validate_device_execution_allowed(device_id)
        if not allowed:
            blocked_result = {
                "device_id": device_id,
                "success": False,
                "message": block_message or "Execucao bloqueada por politica de estado.",
                "failure_category": block_category or "blocked",
            }
            update_task_meta(
                task_id,
                status="failed",
                progress=100,
                message=blocked_result["message"],
                completed=True,
                result=blocked_result,
            )
            append_task_log(task_id, "Sistema", blocked_result["message"], "warning")
            _track_attempt_outcome(
                outcome="failed",
                category=blocked_result["failure_category"],
                message=blocked_result["message"],
            )
            return blocked_result

        requires_vpn, vpn_group_name = _resolve_device_vpn_requirement(device_id)
        if requires_vpn:
            current_queue = _current_task_queue(self.request)
            if current_queue and current_queue != "vpn_queue":
                queue_msg = (
                    "Dispositivo configurado para VPN, mas a task caiu na fila "
                    f"'{current_queue}'. Reenfileire pela vpn_queue para evitar worker sem NetworkManager."
                )
                blocked_result = {
                    "device_id": device_id,
                    "success": False,
                    "message": queue_msg,
                    "failure_category": "vpn_worker",
                }
                update_task_meta(
                    task_id,
                    status="failed",
                    progress=100,
                    message=queue_msg,
                    completed=True,
                    result=blocked_result,
                )
                append_task_log(task_id, vpn_group_name or "VPN", queue_msg, "error")
                _track_attempt_outcome(
                    outcome="failed",
                    category="vpn_worker",
                    message=queue_msg,
                )
                return blocked_result

            if current_queue == "vpn_queue":
                from app.services.vpn_service import vpn_service, VpnError

                try:
                    vpn_service.ensure_worker_ready()
                except VpnError as exc:
                    worker_msg = f"Worker VPN indisponivel para este backup: {exc}"
                    blocked_result = {
                        "device_id": device_id,
                        "success": False,
                        "message": worker_msg,
                        "failure_category": "vpn_worker",
                    }
                    update_task_meta(
                        task_id,
                        status="failed",
                        progress=100,
                        message=worker_msg,
                        completed=True,
                        result=blocked_result,
                    )
                    append_task_log(task_id, vpn_group_name or "VPN", worker_msg, "error")
                    _track_attempt_outcome(
                        outcome="failed",
                        category="vpn_worker",
                        message=worker_msg,
                    )
                    return blocked_result

        logger.info(f"Iniciando backup do dispositivo {device_id}")
        update_task_meta(
            task_id,
            status="running",
            progress=10,
            message="Iniciando conexao com o dispositivo...",
            completed=False,
        )
        append_task_log(task_id, "Sistema", f"Backup iniciado para dispositivo {device_id}", "info")

        # Circuit breaker: verificar se o jump host está bloqueado
        cb_jump_label = str(base_metric_labels.get("jump_host") or "direct")
        if cb_jump_label != "direct":
            cb_open, cb_reason, cb_retry_after = _check_jump_host_circuit_breaker(cb_jump_label)
            if cb_open:
                cb_result = {
                    'device_id': device_id,
                    'success': False,
                    'message': cb_reason,
                    'failure_category': 'circuit_breaker',
                }
                update_task_meta(
                    task_id, status="failed", progress=100,
                    message=cb_reason, completed=True, result=cb_result,
                )
                append_task_log(task_id, "Sistema", cb_reason, "warning")
                _track_attempt_outcome(
                    outcome="circuit_breaker", category="circuit_breaker", message=cb_reason,
                )
                return cb_result

        with _jump_host_lock_context(device_id, task_id=task_id, bulk_task_id=bulk_task_id) as lock_ctx:
            lock_info = lock_ctx
            backup_exec_started_at = time.monotonic()
            success, message = backup_executor.run_backup_for_device_id(device_id, task_id=task_id)
        if backup_exec_started_at is not None:
            backup_exec_duration_seconds = max(0.0, time.monotonic() - backup_exec_started_at)
        message = (message or "").strip()
        if not success and not message:
            message = "Falha sem mensagem retornada pelo executor."
        failure_category = classify_failure(message) if not success else None
        
        result = {
            'device_id': device_id,
            'success': success,
            'message': message,
            'failure_category': failure_category,
        }
        
        if success:
            logger.info(f"Backup concluído com sucesso: {device_id}")
            _record_jump_host_duration(lock_info, backup_exec_duration_seconds, True)
            _adapt_jump_host_slots(lock_info, True, message)
            if cb_jump_label != "direct":
                _record_jump_host_outcome(cb_jump_label, True)
            update_task_meta(
                task_id,
                status="success",
                progress=100,
                message=message or "Backup concluido com sucesso.",
                completed=True,
                result=result,
            )
            append_task_log(task_id, "Sistema", "Backup finalizado com sucesso.", "success")
            _track_attempt_outcome(
                outcome="success",
                category="none",
                message=message,
            )
        else:
            _adapt_jump_host_slots(lock_info, False, message)
            if cb_jump_label != "direct":
                # Circuit breaker do Jump Host deve refletir apenas falhas de TRANSPORTE/JH.
                # Falhas de credencial do dispositivo (auth/InvalidToken/script) nao devem
                # contaminar a saude do bastion e abrir CB em cascata.
                if failure_category == "banner_timeout":
                    _record_jump_host_outcome(cb_jump_label, True)
                elif failure_category in CB_FAILURE_CATEGORIES:
                    _record_jump_host_outcome(cb_jump_label, False)

            logger.warning(f"Backup falhou: {device_id} - {message}")

            retries_done = int(self.request.retries or 0)
            max_retries_allowed = int(self.max_retries or 0)
            should_retry = (
                not bool(bulk_task_id)
                and retries_done < max_retries_allowed
                and not _should_stop_now(bulk_task_id)
                and _should_retry_transient_failure(
                    failure_category, message,
                    device_name=device_name_hint,
                    device_id=str(device_id),
                )
            )
            if should_retry:
                retry_countdown = 30 + retries_done * 30
                append_task_log(
                    task_id, "Sistema",
                    f"Falha transitória ({failure_category}). Retentando em {retry_countdown}s "
                    f"(tentativa {retries_done + 1}/{max_retries_allowed}).",
                    "warning",
                )
                update_task_meta(
                    task_id,
                    status="retrying",
                    progress=0,
                    message=f"Falha transitória. Retentando em {retry_countdown}s...",
                    completed=False,
                )
                _track_attempt_outcome(
                    outcome="retry_scheduled",
                    category=failure_category or "failure",
                    message=message,
                    retry_scheduled=True,
                )
                raise self.retry(args=[device_id, bulk_task_id], countdown=retry_countdown)

            update_task_meta(
                task_id,
                status="failed",
                progress=100,
                message=message or "Backup finalizado com falha.",
                completed=True,
                result=result,
            )
            append_task_log(task_id, "Sistema", "Backup finalizado com falha.", "error")
            _track_attempt_outcome(
                outcome="failed",
                category=failure_category or "failure",
                message=message,
            )

        return result
    except Retry:
        raise
    except JumpHostSlotCancelledError as e:
        logger.warning("Backup interrompido aguardando slot do Jump Host: %s", e)
        result = {
            'device_id': device_id,
            'success': False,
            'message': str(e),
            'failure_category': 'cancelled',
        }
        update_task_meta(
            task_id,
            status="stopped",
            progress=100,
            message=str(e),
            completed=True,
            result=result,
        )
        append_task_log(task_id, "Sistema", str(e), "warning")
        _track_attempt_outcome(
            outcome="stopped",
            category="jump_host_slot_cancelled",
            message=str(e),
        )
        return result
    except JumpHostSlotTimeoutError as e:
        logger.warning("Timeout aguardando slot do Jump Host: %s", e)
        if not lock_info:
            lock_info = _resolve_jump_host_lock(device_id)
        _adapt_jump_host_slots(lock_info, False, str(e))
        result = {
            'device_id': device_id,
            'success': False,
            'message': str(e),
            'failure_category': 'jump_host_slot_timeout',
        }
        update_task_meta(
            task_id,
            status="failed",
            progress=100,
            message=str(e),
            completed=True,
            result=result,
        )
        append_task_log(task_id, "Sistema", str(e), "error")
        _track_attempt_outcome(
            outcome="failed",
            category="jump_host_slot_timeout",
            message=str(e),
        )
        return result
    except Exception as e:
        error_text = _safe_error_text(e)
        logger.error(f"Erro ao executar backup {device_id}: {error_text}")
        if not lock_info:
            lock_info = _resolve_jump_host_lock(device_id)
        _adapt_jump_host_slots(lock_info, False, error_text)
        failure_category = classify_failure(error_text) or "task_exception"

        task_error_result = {
            'device_id': device_id,
            'success': False,
            'message': f"Erro na task: {error_text}",
            'failure_category': failure_category,
        }
        update_task_meta(
            task_id, status="failed", progress=100,
            message=f"Erro na task: {error_text}", completed=True, result=task_error_result,
        )
        append_task_log(task_id, "Sistema", f"Erro na task ({failure_category}): {error_text}", "error")
        _track_attempt_outcome(
            outcome="failed", category=failure_category, message=error_text,
        )
        return task_error_result
    finally:
        try:
            _maybe_finalize_bulk_and_schedule_followup(bulk_task_id)
        except Exception:
            logger.exception("Falha ao avaliar finalizacao do lote pai %s", bulk_task_id)


@celery_app.task(bind=True)
def enqueue_jump_and_vpn_after_direct_phase_task(
    self,
    direct_phase_results,
    tenant_id: str,
    jump_groups_payload=None,
    vpn_groups_payload=None,
    bulk_task_id: str = None,
):
    """
    Callback da fase direta do backup em massa.
    Fase 2: enfileira dispositivos Jump Host individualmente no jump_queue.
    Fase 3: enfileira grupos VPN apenas após concluir a fase Jump.
    """
    from celery import chord
    from sqlalchemy.orm import joinedload
    from app.models.device import Device
    from app.services.realtime_backup_logs import (
        append_task_log,
        get_redis_client,
        get_task_meta,
        register_task,
        update_task_meta,
    )
    import uuid

    jump_groups_payload = jump_groups_payload or []
    vpn_groups_payload = vpn_groups_payload or []
    tenant_id = str(tenant_id)
    task_id = self.request.id

    if not jump_groups_payload:
        # Sem fase Jump: delega direto para callback já existente da fase VPN.
        return enqueue_vpn_groups_after_direct_phase_task.run(
            direct_phase_results,
            tenant_id,
            vpn_groups_payload,
            bulk_task_id,
        )

    if _should_stop_now(bulk_task_id):
        if bulk_task_id:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                "Parada solicitada. Grupos Jump/VPN nao foram enfileirados apos a fase direta.",
                "warning",
            )
            update_task_meta(
                bulk_task_id,
                status="stopping",
                message="Parada solicitada. Fases Jump/VPN nao serao iniciadas.",
            )
        return {"queued_jump_groups": 0, "queued_vpn_groups": 0, "task_ids": [], "stopped": True}

    queued_jump = 0
    queued_jump_groups = 0
    new_task_ids = []
    new_task_device_count = {}
    jump_signatures = []
    device_name_by_id = {}
    device_group_by_id = {}
    device_bastion_by_id = {}

    all_jump_device_ids = []
    for item in jump_groups_payload:
        all_jump_device_ids.extend(list((item or {}).get("device_ids") or []))

    # Resolve nome/grupo/bastion de cada dispositivo Jump para registrar e, principalmente,
    # para intercalar o enfileiramento por bastion (round-robin + stagger).
    jump_device_uuids = []
    for raw_device_id in all_jump_device_ids:
        try:
            jump_device_uuids.append(uuid.UUID(str(raw_device_id)))
        except Exception:
            continue
    if jump_device_uuids:
        db = SessionLocal()
        try:
            rows = db.query(Device).options(joinedload(Device.group)).filter(
                Device.tenant_id == tenant_id,
                Device.id.in_(jump_device_uuids),
            ).all()
            for row in rows:
                device_name_by_id[str(row.id)] = str(row.name or row.id)
                device_group_by_id[str(row.id)] = str(row.group_id) if row.group_id else None
                grp = getattr(row, "group", None)
                device_bastion_by_id[str(row.id)] = (
                    _bastion_key_for_group_fields(
                        getattr(grp, "jump_host", None), getattr(grp, "jump_port", 22)
                    )
                    if grp
                    else "sem-bastion"
                )
        finally:
            db.close()

    # Coleta (device_id, group_id, group_name) de todos os grupos, sem duplicar.
    jump_entries = []
    seen_devices = set()
    for item in jump_groups_payload:
        group_id = str((item or {}).get("group_id") or "").strip()
        group_name = str((item or {}).get("group_name") or group_id or "Grupo Jump Host").strip()
        device_ids = sorted(set((item or {}).get("device_ids") or []))
        if not group_id or not device_ids:
            continue
        queued_jump_groups += 1
        for device_id in device_ids:
            did = str(device_id)
            if did in seen_devices:
                continue
            seen_devices.add(did)
            jump_entries.append((did, group_id, group_name))

    # Round-robin por bastion + stagger: bastions diferentes em paralelo (rapido),
    # mesmo bastion espacado no tempo (nao satura).
    ordered_entries = _interleave_by_bastion(
        jump_entries,
        lambda e: device_bastion_by_id.get(e[0], "sem-bastion"),
    )
    jump_bastion_counts = Counter(
        device_bastion_by_id.get(device_id, "sem-bastion")
        for device_id, _group_id, _group_name in jump_entries
    )
    if bulk_task_id and jump_bastion_counts:
        _store_bulk_jump_bastion_counts(get_redis_client(), bulk_task_id, jump_bastion_counts)

    for (device_id, group_id, group_name), countdown in ordered_entries:
        jump_task_id = str(uuid.uuid4())
        sig = run_backup_task.s(str(device_id), bulk_task_id).set(
            task_id=jump_task_id,
            queue="jump_queue",
            countdown=countdown,
        )
        jump_signatures.append(sig)
        queued_jump += 1
        new_task_ids.append(jump_task_id)
        new_task_device_count[jump_task_id] = 1

        if bulk_task_id:
            register_task(
                task_id=jump_task_id,
                tenant_id=tenant_id,
                device_id=str(device_id),
                device_name=device_name_by_id.get(str(device_id)) or f"Jump Host {group_name}",
                group_id=device_group_by_id.get(str(device_id)) or group_id,
            )
            update_task_meta(
                jump_task_id,
                device_ids=[str(device_id)],
                device_total=1,
            )

    if not jump_signatures:
        # Nada para Jump: segue direto para VPN.
        if vpn_groups_payload:
            return enqueue_vpn_groups_after_direct_phase_task.run(
                direct_phase_results,
                tenant_id,
                vpn_groups_payload,
                bulk_task_id,
            )
        return {"queued_jump_groups": 0, "queued_vpn_groups": 0, "task_ids": []}

    if bulk_task_id:
        current = get_task_meta(bulk_task_id) or {}
        current_child_ids = [str(tid) for tid in (current.get("child_task_ids") or []) if tid]
        merged_child_ids = list(dict.fromkeys(current_child_ids + new_task_ids))

        child_count = current.get("child_task_device_count") or {}
        if not isinstance(child_count, dict):
            child_count = {}
        for k, v in new_task_device_count.items():
            child_count[str(k)] = int(v)

        total_tasks = int(current.get("total_tasks") or 0)
        pending_vpn = len(vpn_groups_payload) if vpn_groups_payload else 0
        min_expected = len(merged_child_ids) + pending_vpn
        if total_tasks < min_expected:
            total_tasks = min_expected

        update_task_meta(
            bulk_task_id,
            child_task_ids=merged_child_ids,
            child_task_device_count=child_count,
            jump_bastion_device_counts=dict(jump_bastion_counts),
            jump_window_seconds=JUMP_HOST_WINDOW_SECONDS,
            jump_window_adaptive_enabled=JUMP_HOST_WINDOW_ADAPTIVE_ENABLED,
            total_tasks=total_tasks,
            status="running",
            message=(
                f"Fase Jump Host iniciada com {queued_jump} dispositivo(s) "
                f"em {queued_jump_groups} grupo(s). "
                f"Fase VPN pendente: {pending_vpn} grupo(s)."
            ),
        )
        append_task_log(
            bulk_task_id,
            "Backup em massa",
            (
                f"Fase 2 (Jump Host) enfileirada com {queued_jump} dispositivo(s) "
                f"de {queued_jump_groups} grupo(s). "
                f"Fase 3 (VPN): {len(vpn_groups_payload)} grupo(s) aguardando callback."
            ),
            "info",
        )

    if vpn_groups_payload:
        callback_sig = enqueue_vpn_groups_after_direct_phase_task.s(
            tenant_id,
            vpn_groups_payload,
            bulk_task_id,
        ).set(queue="jump_queue")
        chord(jump_signatures)(callback_sig)
    else:
        for sig in jump_signatures:
            sig.apply_async()

    append_task_log(
        task_id,
        "Sistema",
        (
            f"Callback da fase direta finalizado. Dispositivos Jump enfileirados: {queued_jump} "
            f"(em {queued_jump_groups} grupo(s)). "
            f"Grupos VPN pendentes: {len(vpn_groups_payload)}."
        ),
        "info",
    )
    return {
        "queued_jump_devices": queued_jump,
        "queued_jump_groups": queued_jump_groups,
        "queued_vpn_groups": len(vpn_groups_payload),
        "task_ids": new_task_ids,
    }


@celery_app.task(bind=True)
def enqueue_vpn_groups_after_direct_phase_task(
    self,
    direct_phase_results,
    tenant_id: str,
    vpn_groups_payload=None,
    bulk_task_id: str = None,
):
    """
    Callback da fase direta do backup em massa.
    Só enfileira grupos VPN após concluir os dispositivos sem VPN.
    """
    from app.services.realtime_backup_logs import (
        append_task_log,
        get_task_meta,
        register_task,
        update_task_meta,
    )

    vpn_groups_payload = vpn_groups_payload or []
    tenant_id = str(tenant_id)
    task_id = self.request.id

    if not vpn_groups_payload:
        if bulk_task_id:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                "Fase direta concluida. Nenhum grupo VPN pendente.",
                "info",
            )
        return {"queued_vpn_groups": 0, "task_ids": []}

    if _should_stop_now(bulk_task_id):
        if bulk_task_id:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                "Parada solicitada. Grupos VPN nao foram enfileirados apos a fase direta.",
                "warning",
            )
            update_task_meta(
                bulk_task_id,
                status="stopping",
                message="Parada solicitada. Fase VPN nao sera iniciada.",
            )
        return {"queued_vpn_groups": 0, "task_ids": [], "stopped": True}

    queued = 0
    new_task_ids = []
    new_task_device_count = {}

    for item in vpn_groups_payload:
        group_id = str((item or {}).get("group_id") or "").strip()
        device_ids = sorted(set((item or {}).get("device_ids") or []))
        if not group_id or not device_ids:
            continue

        vpn_args = [group_id, tenant_id, device_ids]
        force_vpn = bool((item or {}).get("force_vpn"))
        if bulk_task_id:
            vpn_args.append(bulk_task_id)
        task = run_vpn_group_backups_task.apply_async(
            args=vpn_args,
            kwargs={"force_vpn": force_vpn},
            queue="vpn_queue",
        )
        queued += 1
        task_id_str = str(task.id)
        new_task_ids.append(task_id_str)
        new_task_device_count[task_id_str] = len(device_ids)

        if bulk_task_id:
            register_task(
                task_id=task_id_str,
                tenant_id=tenant_id,
                device_name=f"Grupo VPN {group_id}",
                group_id=group_id,
            )
            update_task_meta(
                task_id_str,
                device_ids=list(device_ids),
                device_total=len(device_ids),
            )

    if bulk_task_id:
        current = get_task_meta(bulk_task_id) or {}
        current_child_ids = [str(tid) for tid in (current.get("child_task_ids") or []) if tid]
        merged_child_ids = list(dict.fromkeys(current_child_ids + new_task_ids))

        child_count = current.get("child_task_device_count") or {}
        if not isinstance(child_count, dict):
            child_count = {}
        for k, v in new_task_device_count.items():
            child_count[str(k)] = int(v)

        total_tasks = int(current.get("total_tasks") or 0)
        if total_tasks < len(merged_child_ids):
            total_tasks = len(merged_child_ids)

        update_task_meta(
            bulk_task_id,
            child_task_ids=merged_child_ids,
            child_task_device_count=child_count,
            total_tasks=total_tasks,
            status="running",
            message=(
                f"Fase direta concluida. {queued} grupo(s) VPN enfileirado(s) "
                "para a fase final."
            ),
        )
        append_task_log(
            bulk_task_id,
            "Backup em massa",
            (
                f"Fase direta concluida. Enfileirado(s) {queued} grupo(s) VPN "
                "somente apos finalizar os dispositivos sem VPN."
            ),
            "info",
        )

    append_task_log(
        task_id,
        "Sistema",
        f"Callback da fase direta finalizado. Grupos VPN enfileirados: {queued}.",
        "info",
    )
    return {"queued_vpn_groups": queued, "task_ids": new_task_ids}


@celery_app.task(bind=True)
def run_backup_group_task(self, group_id: str, tenant_id: str):
    """
    Task assíncrona para executar backup de todos os dispositivos de um grupo.
    
    Args:
        group_id: UUID do grupo
        tenant_id: UUID do tenant
    
    Returns:
        Dict com resumo dos resultados
    """
    from app.models.device import Device
    from app.models.device_group import DeviceGroup
    import uuid
    
    db = SessionLocal()
    
    try:
        logger.info(f"Iniciando backup em massa do grupo {group_id}")
        group_uuid = uuid.UUID(group_id)
        group = db.query(DeviceGroup).filter(
            DeviceGroup.id == group_uuid,
            DeviceGroup.tenant_id == tenant_id
        ).first()
        if not group:
            return {'error': f'Grupo {group_id} não encontrado para o tenant informado.'}
        if not bool(getattr(group, "is_active", True)):
            logger.info("Grupo %s inativo; backup de grupo ignorado.", group_id)
            return {
                'group_id': group_id,
                'total': 0,
                'success': 0,
                'failed': 0,
                'skipped': 0,
                'details': [],
                'message': f'Grupo {group.name} inativo. Execucao ignorada.',
            }

        devices = db.query(Device).filter(
            Device.group_id == group_uuid,
            Device.tenant_id == tenant_id,
            Device.is_active == True
        ).all()
        
        results = {
            'group_id': group_id,
            'total': len(devices),
            'success': 0,
            'failed': 0,
            'skipped': 0,
            'details': []
        }
        
        scheduled_devices = [d for d in devices if d.backup_scheduled]
        if uses_vpn_tunnel(group) and scheduled_devices:
            task = run_vpn_group_backups_task.apply_async(
                args=[group_id, tenant_id, [str(d.id) for d in scheduled_devices]],
                queue='vpn_queue'
            )
            results['details'].append({
                'group_name': group.name,
                'task_id': task.id,
                'mode': 'vpn_group'
            })
            logger.info(
                "Grupo %s enfileirado na vpn_queue (%s dispositivos)",
                group_id, len(scheduled_devices)
            )
            return results

        for device in scheduled_devices:
            # Roteia por tipo de conexao para isolar concorrencia:
            # - VPN -> vpn_queue
            # - Jump Host -> jump_queue
            # - Direto -> celery
            if uses_vpn_tunnel(group, device=device):
                target_queue = 'vpn_queue'
            elif uses_jump_host(group, device=device):
                target_queue = 'jump_queue'
            else:
                target_queue = 'celery'
            task = run_backup_task.apply_async(args=[str(device.id)], queue=target_queue)
            results['details'].append({
                'device_id': str(device.id),
                'device_name': device.name,
                'task_id': task.id,
                'queue': target_queue,
            })
        
        logger.info(f"Grupo {group_id}: {len(results['details'])} backups enfileirados")
        return results
    except Exception as e:
        logger.error(f"Erro no backup do grupo {group_id}: {e}")
        return {'error': str(e)}
    finally:
        db.close()


@celery_app.task(bind=True, queue='vpn_queue')
def run_vpn_group_backups_task(
    self,
    group_id: str,
    tenant_id: str,
    device_ids=None,
    bulk_task_id: str = None,
    force_vpn: bool = False,
):
    """
    Executa backups de um grupo VPN em sessão única:
    conecta VPN -> executa backups -> desconecta VPN.
    """
    from app.models.device import Device
    from app.models.device_group import DeviceGroup
    from app.services.backup_executor import backup_executor
    from app.services.vpn_service import vpn_service, VpnError
    from app.services.realtime_backup_logs import append_task_log, update_task_meta
    from app.services.backup_diagnostics import classify_failure
    import uuid

    from sqlalchemy.orm import joinedload

    db = SessionLocal()
    device_ids = device_ids or []
    task_id = self.request.id

    try:
        _touch_bulk_activity(bulk_task_id)
        group_uuid = uuid.UUID(group_id)
        group = db.query(DeviceGroup).filter(
            DeviceGroup.id == group_uuid,
            DeviceGroup.tenant_id == tenant_id
        ).first()
        if not group:
            update_task_meta(
                task_id,
                status="failed",
                progress=100,
                message=f"Grupo {group_id} nao encontrado.",
                completed=True,
                error=f"Grupo {group_id} nao encontrado.",
            )
            return {'error': f'Grupo {group_id} não encontrado.'}
        if not bool(getattr(group, "is_active", True)):
            inactive_msg = f'Grupo {group.name} inativo. Execucao VPN bloqueada.'
            update_task_meta(
                task_id,
                status="failed",
                progress=100,
                message=inactive_msg,
                completed=True,
                error=inactive_msg,
            )
            append_task_log(task_id, group.name, inactive_msg, "warning")
            return {'error': inactive_msg, 'group_id': group_id}

        query = db.query(Device).options(
            joinedload(Device.group),
            joinedload(Device.subgroup),
            joinedload(Device.type),
        ).filter(
            Device.tenant_id == tenant_id,
            Device.group_id == group_uuid,
            Device.is_active == True,
            Device.backup_scheduled == True
        )
        if device_ids:
            query = query.filter(Device.id.in_(device_ids))
        devices = query.all()
        
        # Touch relationships to ensure they are cached locally on the object,
        # especially for None values which might otherwise trigger lazy loads.
        # Tambem cacheia o modo de conexao efetivo por dispositivo antes de
        # desanexar a sessao (evita qualquer lazy-load posterior de subgroup).
        device_connection_flags = {}
        for d in devices:
            _ = d.group
            _ = d.subgroup
            _ = d.type
            device_connection_flags[str(d.id)] = {
                "vpn": bool(uses_vpn_tunnel(group, device=d)),
                "jump": bool(uses_jump_host(group, device=d)),
            }

        # Evita manter conexao/transacao de DB aberta durante tentativas longas de VPN/L2TP.
        # expunge_all() desanexa os objetos da sessao, mantendo os atributos eager-loaded
        # (group, subgroup, type) acessiveis em memoria sem tentar lazy load.
        db.expunge_all()
        db.close()

        result = {
            'group_id': group_id,
            'group_name': group.name,
            'mode': 'group',
            'total': len(devices),
            'success': 0,
            'failed': 0,
            'details': []
        }

        if not devices:
            update_task_meta(
                task_id,
                status="success",
                progress=100,
                message="Nenhum dispositivo elegivel para backup.",
                completed=True,
                result=result,
            )
            return result

        if _should_stop_now(bulk_task_id):
            result["failed"] = len(devices)
            result["details"].append({
                "device_id": None,
                "device_name": "Lote",
                "success": False,
                "message": "Interrompido por parada forçada antes do inicio da execucao."
            })
            update_task_meta(
                task_id,
                status="stopped",
                progress=100,
                message=f"Grupo {group.name} interrompido por parada forçada.",
                completed=True,
                result=result,
            )
            append_task_log(task_id, group.name, "Execucao do grupo interrompida por parada forçada.", "warning")
            return result

        update_task_meta(
            task_id,
            status="running",
            progress=5,
            message=f"Iniciando processamento do grupo {group.name}...",
            completed=False,
            total_devices=len(devices),
            processed_devices=0,
            done_devices=0,
            success_devices=0,
            failed_devices=0,
            current_device_name=None,
            current_device_index=0,
            current_device_fraction=0.0,
        )
        append_task_log(task_id, group.name, "Iniciando workflow do grupo.", "info")
        if force_vpn:
            append_task_log(task_id, group.name, "Modo VPN forçado por subgrupo de conexão.", "info")
        _touch_bulk_activity(bulk_task_id)

        vpn_required_devices = []
        if force_vpn:
            vpn_required_devices = list(devices)
        else:
            vpn_required_devices = [
                device
                for device in devices
                if bool((device_connection_flags.get(str(device.id)) or {}).get("vpn"))
            ]
        use_vpn_mode = bool(vpn_required_devices)
        result["mode"] = "vpn_group" if use_vpn_mode else "group_direct"
        if force_vpn:
            append_task_log(
                task_id,
                group.name,
                f"VPN exigida para {len(vpn_required_devices)}/{len(devices)} dispositivo(s) (modo forçado).",
                "info",
            )
        else:
            append_task_log(
                task_id,
                group.name,
                f"VPN exigida para {len(vpn_required_devices)}/{len(devices)} dispositivo(s) deste lote.",
                "info",
            )

        if use_vpn_mode:
            vpn_service.ensure_worker_ready()

        def _execute_device_with_guards(device_obj, *, manage_vpn_flag: bool):
            """Executa 1 dispositivo com lock/circuit-breaker de Jump Host também no fluxo por grupo."""
            local_lock_info = None
            cb_jump_label = "direct"
            cb_retry_after = 0
            conn_flags = device_connection_flags.get(str(device_obj.id)) or {}
            use_jump_for_device = bool(conn_flags.get("jump"))

            if (
                getattr(device_obj, "group", None)
                and use_jump_for_device
                and getattr(device_obj.group, "jump_host", None)
            ):
                cb_jump_label = f"{device_obj.group.jump_host}:{int(getattr(device_obj.group, 'jump_port', 22) or 22)}"
                cb_open, cb_reason, cb_retry_after = _check_jump_host_circuit_breaker(cb_jump_label)
                if cb_open:
                    return False, cb_reason, "circuit_breaker", int(cb_retry_after or 0)

            try:
                with _jump_host_lock_context(str(device_obj.id), task_id=task_id, bulk_task_id=bulk_task_id) as lock_ctx:
                    local_lock_info = lock_ctx
                    success, message = backup_executor.run_backup_for_device_id(
                        str(device_obj.id),
                        manage_vpn=manage_vpn_flag,
                        task_id=task_id,
                    )
            except JumpHostSlotTimeoutError as exc:
                success, message = False, str(exc)
            except JumpHostSlotCancelledError as exc:
                success, message = False, str(exc)

            message = (message or "").strip() or "Falha sem mensagem retornada pelo executor."
            failure_category = classify_failure(message) if not success else None

            _adapt_jump_host_slots(local_lock_info, bool(success), message)
            if cb_jump_label != "direct":
                if success or failure_category == "banner_timeout":
                    _record_jump_host_outcome(cb_jump_label, True)
                elif failure_category in CB_FAILURE_CATEGORIES or failure_category == "circuit_breaker":
                    _record_jump_host_outcome(cb_jump_label, False)

            return bool(success), message, failure_category, int(cb_retry_after or 0)

        if not use_vpn_mode:
            # Fallback de segurança: grupo sem VPN, executa normal.
            append_task_log(task_id, group.name, "Grupo sem VPN, executando fluxo direto.", "warning")
            processed = 0
            cancelled = False
            for device in devices:
                _touch_bulk_activity(bulk_task_id)
                if _should_stop_now(bulk_task_id):
                    cancelled = True
                    remaining = len(devices) - processed
                    result["failed"] += max(0, remaining)
                    result["details"].append({
                        "device_id": None,
                        "device_name": "Lote",
                        "success": False,
                        "message": f"Interrompido por parada forçada com {processed}/{len(devices)} processados."
                    })
                    break
                try:
                    with _device_execution_deadline(VPN_GROUP_DEVICE_MAX_SECONDS):
                        success, message, failure_category, cb_retry_after = _execute_device_with_guards(
                            device,
                            manage_vpn_flag=False,
                        )
                except DeviceExecutionDeadlineExceeded:
                    success = False
                    message = (
                        f"Timeout por dispositivo no grupo direto "
                        f"({VPN_GROUP_DEVICE_MAX_SECONDS}s excedido). "
                        "Possivel SSH/Telnet congelado; demais dispositivos do grupo nao foram bloqueados."
                    )
                    failure_category = "timeout"
                    cb_retry_after = 0
                    logger.error(
                        "Timeout por dispositivo (%ss) no grupo direto %s: %s",
                        VPN_GROUP_DEVICE_MAX_SECONDS, group_id, device.name,
                    )
                if cancelled:
                    break
                if success:
                    result['success'] += 1
                else:
                    result['failed'] += 1
                processed += 1
                progress = min(95, int((processed / max(1, len(devices))) * 100))
                update_task_meta(
                    task_id,
                    status="running",
                    progress=progress,
                    message=f"Processando {processed}/{len(devices)} dispositivos...",
                    completed=False,
                )
                result['details'].append({
                    'device_id': str(device.id),
                    'device_name': device.name,
                    'success': success,
                    'message': message,
                    'failure_category': failure_category,
                })
            final_status = "stopped" if cancelled else ("success" if result["failed"] == 0 else "failed")
            final_msg = (
                f"Interrompido. Sucesso: {result['success']} | Falhas: {result['failed']}"
                if cancelled
                else f"Finalizado. Sucesso: {result['success']} | Falhas: {result['failed']}"
            )
            update_task_meta(
                task_id,
                status=final_status,
                progress=100,
                message=final_msg,
                completed=True,
                result=result,
            )
            append_task_log(
                task_id,
                group.name,
                final_msg,
                "success" if final_status == "success" else "error",
            )
            return result

        append_task_log(task_id, group.name, "Conectando VPN do grupo...", "info")
        with vpn_service.vpn_session(
            group,
            logger=logger,
            timeout_seconds=VPN_GLOBAL_LOCK_TIMEOUT_SECONDS,
        ):
            append_task_log(task_id, group.name, "VPN conectada com sucesso.", "success")
            processed = 0
            cancelled = False
            bulk_fail_fast = bool(bulk_task_id) and len(devices) >= LARGE_BULK_FAIL_FAST_THRESHOLD
            if bulk_fail_fast:
                append_task_log(
                    task_id,
                    group.name,
                    (
                        f"Modo fail-fast habilitado para lote grande ({len(devices)} dispositivos): "
                        "falhas transitorias nao terao retentativas para evitar travamento do lote."
                    ),
                    "warning",
                )
            for device in devices:
                _touch_bulk_activity(bulk_task_id)
                if _should_stop_now(bulk_task_id):
                    cancelled = True
                    remaining = len(devices) - processed
                    result["failed"] += max(0, remaining)
                    result["details"].append({
                        "device_id": None,
                        "device_name": "Lote",
                        "success": False,
                        "message": f"Interrompido por parada forçada com {processed}/{len(devices)} processados."
                    })
                    append_task_log(task_id, group.name, "Parada forçada solicitada. Interrompendo dispositivos restantes.", "warning")
                    break
                update_task_meta(
                    task_id,
                    status="running",
                    progress=_multi_device_progress(len(devices), processed, 0.2),
                    message=f"Processando {processed + 1}/{len(devices)} via VPN: {device.name}",
                    completed=False,
                    total_devices=len(devices),
                    processed_devices=processed,
                    done_devices=processed,
                    success_devices=result["success"],
                    failed_devices=result["failed"],
                    current_device_name=device.name,
                    current_device_index=processed + 1,
                    current_device_fraction=0.2,
                )
                try:
                    with _device_execution_deadline(VPN_GROUP_DEVICE_MAX_SECONDS):
                        success, message, failure_category, cb_retry_after = _execute_device_with_guards(
                            device,
                            manage_vpn_flag=False,
                        )
                except DeviceExecutionDeadlineExceeded:
                    success = False
                    message = (
                        f"Timeout por dispositivo no grupo VPN "
                        f"({VPN_GROUP_DEVICE_MAX_SECONDS}s excedido). "
                        "Possivel SSH/Telnet congelado; demais dispositivos do grupo nao foram bloqueados."
                    )
                    failure_category = "timeout"
                    cb_retry_after = 0
                    logger.error(
                        "Timeout por dispositivo (%ss) no grupo VPN %s: %s",
                        VPN_GROUP_DEVICE_MAX_SECONDS, group_id, device.name,
                    )
                if cancelled:
                    break
                if success:
                    result['success'] += 1
                else:
                    result['failed'] += 1
                processed += 1
                update_task_meta(
                    task_id,
                    status="running",
                    progress=_multi_device_progress(len(devices), processed, 0.0),
                    message=f"Processando {processed}/{len(devices)} dispositivos via VPN...",
                    completed=False,
                    total_devices=len(devices),
                    processed_devices=processed,
                    done_devices=processed,
                    success_devices=result["success"],
                    failed_devices=result["failed"],
                    current_device_name=device.name,
                    current_device_index=processed,
                    current_device_fraction=0.0,
                )
                result['details'].append({
                    'device_id': str(device.id),
                    'device_name': device.name,
                    'success': success,
                    'message': message,
                    'failure_category': failure_category,
                })
        append_task_log(task_id, group.name, "Desconectando VPN do grupo.", "info")
        _touch_bulk_activity(bulk_task_id)

        logger.info(
            "VPN group backup finalizado: group=%s success=%s failed=%s total=%s",
            group_id, result['success'], result['failed'], result['total']
        )
        final_status = "stopped" if cancelled else ("success" if result["failed"] == 0 else "failed")
        final_msg = (
            f"Interrompido. Sucesso: {result['success']} | Falhas: {result['failed']}"
            if cancelled
            else f"Finalizado. Sucesso: {result['success']} | Falhas: {result['failed']}"
        )
        update_task_meta(
            task_id,
            status=final_status,
            progress=100,
            message=final_msg,
            completed=True,
            result=result,
            total_devices=len(devices),
            processed_devices=processed if 'processed' in locals() else 0,
            done_devices=processed if 'processed' in locals() else 0,
            success_devices=result["success"],
            failed_devices=result["failed"],
            current_device_name=None,
            current_device_index=0,
            current_device_fraction=0.0,
        )
        append_task_log(
            task_id,
            group.name,
            final_msg,
            "success" if final_status == "success" else "error",
        )
        return result
    except VpnError as e:
        failure_message = f"Falha de VPN: {e}"
        failed_total = len(devices) if "devices" in locals() and devices else 1
        vpn_result = {
            "group_id": group_id,
            "group_name": getattr(group, "name", None) if "group" in locals() else None,
            "mode": "vpn_group",
            "total": failed_total,
            "success": 0,
            "failed": failed_total,
            "error": str(e),
            "details": [
                {
                    "device_id": str(getattr(device, "id", "")) or None,
                    "device_name": getattr(device, "name", "Grupo VPN"),
                    "success": False,
                    "message": failure_message,
                    "failure_category": "vpn",
                }
                for device in (devices if "devices" in locals() and devices else [])
            ],
        }
        if not vpn_result["details"]:
            vpn_result["details"].append({
                "device_id": None,
                "device_name": getattr(group, "name", "Grupo VPN") if "group" in locals() else "Grupo VPN",
                "success": False,
                "message": failure_message,
                "failure_category": "vpn",
            })
        logger.error("Falha de VPN no grupo %s: %s", group_id, e)
        update_task_meta(
            task_id,
            status="failed",
            progress=100,
            message=failure_message,
            completed=True,
            error=str(e),
            result=vpn_result,
            total_devices=failed_total,
            processed_devices=0,
            done_devices=failed_total,
            success_devices=0,
            failed_devices=failed_total,
        )
        append_task_log(task_id, "VPN", failure_message, "error")
        return vpn_result
    except Exception as e:
        logger.exception("Erro no backup VPN do grupo %s", group_id)
        update_task_meta(
            task_id,
            status="failed",
            progress=100,
            message=f"Erro no backup do grupo: {e}",
            completed=True,
            error=str(e),
        )
        append_task_log(task_id, "Sistema", f"Erro no backup do grupo: {e}", "error")
        return {'error': str(e), 'group_id': group_id}
    finally:
        try:
            db.close()
        except Exception:
            # Falha no close nao deve mascarar o erro real do backup (ex.: VPN/PPP).
            pass
        try:
            _maybe_finalize_bulk_and_schedule_followup(bulk_task_id)
        except Exception:
            logger.exception("Falha ao avaliar finalizacao do lote pai %s", bulk_task_id)


@celery_app.task(
    bind=True,
    queue="celery",
    max_retries=BULK_TRANSIENT_FOLLOWUP_MAX_RETRIES,
)
def run_bulk_transient_followup_task(
    self,
    tenant_id: str,
    device_ids=None,
    source_bulk_task_id: str | None = None,
):
    from celery import chord
    from sqlalchemy import or_
    from sqlalchemy.orm import joinedload
    from app.models.device import Device
    from app.models.device_group import DeviceGroup
    from app.services.realtime_backup_logs import (
        acquire_tenant_bulk_lock,
        append_task_log,
        register_task,
        release_tenant_bulk_lock,
        update_task_meta,
    )

    task_id = str(self.request.id)
    tenant_id = str(tenant_id or "").strip()
    requested_device_ids = sorted({str(v).strip() for v in (device_ids or []) if str(v).strip()})
    if not tenant_id or not requested_device_ids:
        return {"ok": False, "error": "Parametros insuficientes para reprocessamento automatico."}

    source_bulk_meta = _safe_get_task_meta(str(source_bulk_task_id)) if source_bulk_task_id else {}
    source_completed_at = None
    try:
        raw_completed_at = str(source_bulk_meta.get("completed_at") or "").strip()
        if raw_completed_at:
            source_completed_at = datetime.fromisoformat(raw_completed_at.replace("Z", "+00:00"))
    except Exception:
        source_completed_at = None

    retries_done = int(self.request.retries or 0)
    lock_acquired, existing_task_id = acquire_tenant_bulk_lock(str(tenant_id), task_id)
    if not lock_acquired:
        wait_msg = (
            f"Tenant com outro lote ativo ({existing_task_id}). "
            f"Reprocessamento automatico aguardara {BULK_TRANSIENT_FOLLOWUP_BUSY_RETRY_SECONDS}s."
        )
        if source_bulk_task_id and retries_done == 0:
            update_task_meta(
                str(source_bulk_task_id),
                transient_followup_status="waiting_lock",
                transient_followup_blocked_by=str(existing_task_id or ""),
            )
            append_task_log(str(source_bulk_task_id), "Reprocessamento automatico", wait_msg, "warning")
        raise self.retry(countdown=BULK_TRANSIENT_FOLLOWUP_BUSY_RETRY_SECONDS)

    register_task(
        task_id=task_id,
        tenant_id=str(tenant_id),
        device_name="Reprocessamento automatico",
        group_id=None,
    )

    db = SessionLocal()
    try:
        if source_bulk_task_id:
            update_task_meta(
                str(source_bulk_task_id),
                transient_followup_status="starting",
                transient_followup_bulk_task_id=task_id,
                transient_followup_started_at=datetime.utcnow().isoformat() + "Z",
            )

        update_task_meta(
            task_id,
            is_bulk=True,
            operation_kind="backup_reprocess",
            auto_followup=True,
            transient_only=True,
            source_bulk_task_id=str(source_bulk_task_id or ""),
            status="running",
            progress=2,
            completed=False,
            message=f"Preparando reprocessamento automatico para {len(requested_device_ids)} dispositivo(s)...",
            total_devices=0,
            total_tasks=0,
            done_tasks=0,
            success_tasks=0,
            failed_tasks=0,
            running_tasks=0,
            queued_tasks=0,
            child_task_ids=[],
            child_task_device_count={},
            finished_task_ids=[],
            group_summary=[],
        )
        append_task_log(
            task_id,
            "Reprocessamento automatico",
            (
                f"Iniciando follow-up automatico do lote {source_bulk_task_id or '-'} "
                f"para {len(requested_device_ids)} dispositivo(s) com falha transitoria."
            ),
            "info",
        )

        parsed_uuid_ids = []
        for raw_id in requested_device_ids:
            try:
                import uuid as _uuid
                parsed_uuid_ids.append(_uuid.UUID(raw_id))
            except Exception:
                continue

        devices = (
            db.query(Device)
            .options(joinedload(Device.group), joinedload(Device.subgroup), joinedload(Device.type))
            .outerjoin(DeviceGroup, Device.group_id == DeviceGroup.id)
            .filter(
                Device.tenant_id == tenant_id,
                Device.id.in_(parsed_uuid_ids),
                Device.is_active == True,
                Device.backup_scheduled == True,
                or_(Device.group_id.is_(None), DeviceGroup.is_active.is_(True)),
            )
            .all()
        )

        recovered_devices = []
        active_devices = []
        for device in devices:
            if (
                source_completed_at is not None
                and getattr(device, "last_backup_at", None) is not None
                and str(getattr(device, "last_backup_status", "") or "").strip().lower() == "success"
            ):
                last_backup_at = getattr(device, "last_backup_at", None)
                try:
                    if getattr(last_backup_at, "tzinfo", None) is None:
                        last_backup_at = last_backup_at.replace(tzinfo=source_completed_at.tzinfo)
                except Exception:
                    pass
                try:
                    if last_backup_at and last_backup_at >= source_completed_at:
                        recovered_devices.append(device)
                        continue
                except Exception:
                    pass
            active_devices.append(device)
        devices = active_devices

        excluded_type_ids = resolve_mass_backup_excluded_type_ids(db)
        devices, excluded_mass_devices = _auto_split_mass_backup_devices(devices, excluded_type_ids)
        skipped_mass_excluded = len(excluded_mass_devices)

        devices, jump_preflight_summary = _auto_bulk_preflight_jump_hosts(
            devices,
            tenant_id=str(tenant_id),
        )
        skipped_jump_unreachable = int(jump_preflight_summary.get("skipped_jump_unreachable") or 0)
        skipped_jump_device_ids = list(jump_preflight_summary.get("skipped_device_ids") or [])
        visible_total_devices = len(devices) + len(skipped_jump_device_ids)
        initial_failure_counts = {"connection": len(skipped_jump_device_ids)} if skipped_jump_device_ids else {}

        if not devices:
            final_msg = (
                "Nenhum dispositivo permaneceu elegivel para o reprocessamento automatico "
                f"(recuperados={len(recovered_devices)}, excluidos={skipped_mass_excluded}, "
                f"jump_unreachable={skipped_jump_unreachable})."
            )
            update_task_meta(
                task_id,
                is_bulk=True,
                operation_kind="backup_reprocess",
                auto_followup=True,
                transient_only=True,
                source_bulk_task_id=str(source_bulk_task_id or ""),
                status="success",
                progress=100,
                completed=True,
                message=final_msg,
                total_devices=0,
                total_tasks=0,
                done_tasks=0,
                success_tasks=0,
                failed_tasks=0,
                running_tasks=0,
                queued_tasks=0,
                skipped_already_recovered=len(recovered_devices),
                skipped_mass_excluded=skipped_mass_excluded,
                skipped_jump_unreachable=skipped_jump_unreachable,
                jump_preflight_enabled=bool(jump_preflight_summary.get("enabled")),
                jump_preflight_checked_endpoints=int(jump_preflight_summary.get("checked_endpoints") or 0),
                jump_preflight_total_endpoints=int(jump_preflight_summary.get("total_endpoints") or 0),
                jump_preflight_probe_truncated=bool(jump_preflight_summary.get("probe_truncated")),
                jump_preflight_unreachable_endpoints=list(jump_preflight_summary.get("unreachable_endpoints") or []),
            )
            append_task_log(task_id, "Reprocessamento automatico", final_msg, "info")
            if source_bulk_task_id:
                update_task_meta(
                    str(source_bulk_task_id),
                    transient_followup_status="skipped",
                    transient_followup_bulk_task_id=task_id,
                )
                append_task_log(str(source_bulk_task_id), "Reprocessamento automatico", final_msg, "info")
            return {
                "ok": True,
                "skipped": True,
                "message": final_msg,
            }

        direct_by_group = {}
        jump_by_group = {}
        vpn_by_group = {}
        direct_no_group_devices = []
        throttle_counters = {}
        child_task_ids = []
        child_task_device_count = {}
        direct_signatures = []
        phased_deferred = False

        for device in devices:
            subgroup_mode = _auto_device_subgroup_connection_type(device)
            force_vpn_subgroup = bool(subgroup_mode == "vpn" and device.group and not uses_vpn_tunnel(device.group))

            if device.group and uses_vpn_tunnel(device.group, device=device):
                _auto_append_group_phase_bucket(vpn_by_group, device, force_vpn=force_vpn_subgroup)
                continue
            if device.group and uses_jump_host(device.group, device=device):
                _auto_append_group_phase_bucket(jump_by_group, device)
                continue
            if device.group:
                _auto_append_group_phase_bucket(direct_by_group, device)
            else:
                direct_no_group_devices.append(device)

        direct_payload = _auto_finalize_group_phase_payload(direct_by_group)
        jump_payload = _auto_finalize_group_phase_payload(jump_by_group)
        vpn_payload = _auto_finalize_group_phase_payload(vpn_by_group)

        queued_direct = sum(len(item["device_ids"]) for item in direct_payload) + len(direct_no_group_devices)
        queued_jump = sum(len(item["device_ids"]) for item in jump_payload)
        queued_jump_groups = len(jump_payload)
        queued_vpn_groups = len(vpn_payload)

        for item in direct_payload:
            direct_task_id = f"group-direct-{os.urandom(4).hex()}"
            sig = run_vpn_group_backups_task.s(
                item["group_id"],
                str(tenant_id),
                item["device_ids"],
                task_id,
            ).set(task_id=direct_task_id, queue="celery")
            child_task_ids.append(direct_task_id)
            child_task_device_count[direct_task_id] = len(item["device_ids"])
            register_task(
                task_id=direct_task_id,
                tenant_id=str(tenant_id),
                device_name=f"Grupo Direto {item.get('group_name') or item['group_id']}",
                group_id=item["group_id"],
            )
            update_task_meta(
                direct_task_id,
                device_ids=list(item["device_ids"]),
                device_total=len(item["device_ids"]),
                source_bulk_task_id=str(source_bulk_task_id or ""),
                auto_followup=True,
            )
            direct_signatures.append(sig)

        for device in direct_no_group_devices:
            child_task_id = f"device-direct-{os.urandom(4).hex()}"
            countdown = _auto_next_countdown_for_device(device, throttle_counters)
            target_queue = _auto_backup_queue_for_device(device)
            sig = run_backup_task.s(str(device.id), task_id).set(
                task_id=child_task_id,
                countdown=countdown,
                queue=target_queue,
            )
            child_task_ids.append(child_task_id)
            child_task_device_count[child_task_id] = 1
            register_task(
                task_id=child_task_id,
                tenant_id=str(tenant_id),
                device_id=str(device.id),
                device_name=device.name,
                group_id=str(device.group_id) if device.group_id else None,
            )
            update_task_meta(
                child_task_id,
                source_bulk_task_id=str(source_bulk_task_id or ""),
                auto_followup=True,
            )
            direct_signatures.append(sig)

        if direct_signatures:
            if jump_payload or vpn_payload:
                callback_sig = enqueue_jump_and_vpn_after_direct_phase_task.s(
                    str(tenant_id),
                    jump_payload,
                    vpn_payload,
                    task_id,
                ).set(queue="celery")
                chord(direct_signatures)(callback_sig)
                phased_deferred = True
            else:
                for sig in direct_signatures:
                    sig.apply_async()
        elif jump_payload or vpn_payload:
            enqueue_jump_and_vpn_after_direct_phase_task.apply_async(
                args=[None, str(tenant_id), jump_payload, vpn_payload, task_id],
                queue="celery",
            )
            phased_deferred = True

        total_tasks = len(child_task_ids) + (queued_jump + queued_vpn_groups if phased_deferred else 0)
        update_task_meta(
            task_id,
            is_bulk=True,
            operation_kind="backup_reprocess",
            auto_followup=True,
            transient_only=True,
            source_bulk_task_id=str(source_bulk_task_id or ""),
            status="running",
            progress=5,
            completed=False,
            message=(
                f"{total_tasks} tarefas planejadas para reprocessamento automatico."
                if phased_deferred
                else f"{total_tasks} tarefas enfileiradas para reprocessamento automatico."
            ),
            total_devices=visible_total_devices,
            queued_direct=queued_direct,
            queued_jump=queued_jump,
            queued_jump_groups=queued_jump_groups,
            queued_vpn_groups=queued_vpn_groups,
            total_tasks=total_tasks,
            done_tasks=0,
            success_tasks=0,
            failed_tasks=0,
            done_devices=len(skipped_jump_device_ids),
            success_devices=0,
            failed_devices=len(skipped_jump_device_ids),
            running_tasks=0,
            queued_tasks=total_tasks,
            child_task_ids=child_task_ids,
            child_task_device_count=child_task_device_count,
            finished_task_ids=[],
            group_summary=[],
            skipped_already_recovered=len(recovered_devices),
            skipped_mass_excluded=skipped_mass_excluded,
            skipped_jump_unreachable=skipped_jump_unreachable,
            skipped_jump_device_ids=skipped_jump_device_ids,
            failure_category_counts=initial_failure_counts,
            jump_preflight_enabled=bool(jump_preflight_summary.get("enabled")),
            jump_preflight_checked_endpoints=int(jump_preflight_summary.get("checked_endpoints") or 0),
            jump_preflight_total_endpoints=int(jump_preflight_summary.get("total_endpoints") or 0),
            jump_preflight_probe_truncated=bool(jump_preflight_summary.get("probe_truncated")),
            jump_preflight_unreachable_endpoints=list(jump_preflight_summary.get("unreachable_endpoints") or []),
        )
        append_task_log(
            task_id,
            "Reprocessamento automatico",
            (
                f"Enfileirado: {queued_direct} diretos + {queued_jump} jump + "
                f"{queued_vpn_groups} grupo(s) VPN ({len(devices)} dispositivos)."
            ),
            "success",
        )
        if source_bulk_task_id:
            update_task_meta(
                str(source_bulk_task_id),
                transient_followup_status="running",
                transient_followup_bulk_task_id=task_id,
            )
            append_task_log(
                str(source_bulk_task_id),
                "Reprocessamento automatico",
                (
                    f"Follow-up automatico iniciado com {len(devices)} dispositivo(s). "
                    f"Task bulk: {task_id}"
                ),
                "success",
            )
        return {
            "ok": True,
            "task_id": task_id,
            "total_devices": len(devices),
            "total_tasks": total_tasks,
            "queued_direct": queued_direct,
            "queued_jump": queued_jump,
            "queued_vpn_groups": queued_vpn_groups,
        }
    except Retry:
        raise
    except Exception as exc:
        logger.exception("Falha ao iniciar reprocessamento automatico do lote %s", source_bulk_task_id)
        error_msg = f"Erro ao iniciar reprocessamento automatico: {exc}"
        update_task_meta(
            task_id,
            is_bulk=True,
            operation_kind="backup_reprocess",
            auto_followup=True,
            transient_only=True,
            source_bulk_task_id=str(source_bulk_task_id or ""),
            status="failed",
            progress=100,
            completed=True,
            message=error_msg,
            error=str(exc),
        )
        append_task_log(task_id, "Reprocessamento automatico", error_msg, "error")
        if source_bulk_task_id:
            update_task_meta(
                str(source_bulk_task_id),
                transient_followup_status="failed",
                transient_followup_bulk_task_id=task_id,
            )
            append_task_log(str(source_bulk_task_id), "Reprocessamento automatico", error_msg, "error")
        return {"ok": False, "error": error_msg}
    finally:
        try:
            db.close()
        except Exception:
            pass
        try:
            current = _safe_get_task_meta(task_id)
            if not current or not bool(current.get("is_bulk")):
                release_tenant_bulk_lock(str(tenant_id), task_id)
        except Exception:
            logger.exception("Falha ao liberar lock do reprocessamento automatico %s", task_id)


@celery_app.task
def run_scheduled_backups():
    """
    Task periódica para executar backups agendados de todos os tenants.
    
    Esta task é executada pelo Celery Beat conforme agendamento.
    """
    from app.models.device import Device
    from app.models.schedule import Schedule, ScheduleFrequency
    from app.models.device_group import DeviceGroup
    from sqlalchemy.orm import joinedload
    from sqlalchemy import or_
    
    if _is_global_backup_stop_enabled():
        logger.warning("Bloqueio global de backups ativo; run_scheduled_backups nao enfileirou tarefas.")
        return {
            'schedules_checked': 0,
            'devices_queued': 0,
            'direct_devices_queued': 0,
            'vpn_groups_queued': 0,
            'initialized_next_run': 0,
            'blocked_by_force_stop': True,
        }

    if _has_active_bulk_operation():
        logger.info(
            "Lote bulk ativo detectado; run_scheduled_backups pausado para evitar concorrencia de filas."
        )
        return {
            'schedules_checked': 0,
            'devices_queued': 0,
            'direct_devices_queued': 0,
            'vpn_groups_queued': 0,
            'initialized_next_run': 0,
            'blocked_by_running_bulk': True,
        }

    db = SessionLocal()
    
    try:
        now = utc_now_naive()
        active_device_filters = [
            Device.is_active == True,
            Device.backup_scheduled == True,
            or_(Device.group_id.is_(None), DeviceGroup.is_active.is_(True)),
        ]

        schedule_rows = (
            db.query(Schedule)
            .join(Device)
            .outerjoin(DeviceGroup, Device.group_id == DeviceGroup.id)
            .options(joinedload(Schedule.device).joinedload(Device.group))
            .filter(Schedule.is_active == True, *active_device_filters)
            .all()
        )

        def _tenant_daily_time(tenant_id) -> str:
            tenant_times = [
                sanitize_daily_time(row.time)
                for row in schedule_rows
                if row.device and str(row.device.tenant_id) == str(tenant_id) and row.time
            ]
            if tenant_times:
                return Counter(tenant_times).most_common(1)[0][0]
            return "02:00"

        initialized = 0
        scheduled_device_ids = {str(row.device_id) for row in schedule_rows}
        backup_enabled_devices = (
            db.query(Device)
            .outerjoin(DeviceGroup, Device.group_id == DeviceGroup.id)
            .filter(*active_device_filters)
            .all()
        )

        for device in backup_enabled_devices:
            if str(device.id) in scheduled_device_ids:
                continue
            schedule_time = _tenant_daily_time(device.tenant_id)
            db.add(
                Schedule(
                    device_id=device.id,
                    frequency=ScheduleFrequency.DAILY,
                    time=schedule_time,
                    is_active=True,
                    next_run_at=compute_next_daily_run_at(time_str=schedule_time, reference_utc=now),
                )
            )
            initialized += 1

        if initialized:
            db.flush()
            schedule_rows = (
                db.query(Schedule)
                .join(Device)
                .outerjoin(DeviceGroup, Device.group_id == DeviceGroup.id)
                .options(joinedload(Schedule.device).joinedload(Device.group))
                .filter(Schedule.is_active == True, *active_device_filters)
                .all()
            )

        due_tenant_ids = set()
        for schedule in schedule_rows:
            schedule.frequency = ScheduleFrequency.DAILY
            schedule.day_of_week = None
            schedule.day_of_month = None
            if not schedule.time:
                schedule.time = _tenant_daily_time(schedule.device.tenant_id if schedule.device else None)
            else:
                schedule.time = sanitize_daily_time(schedule.time)
            if not schedule.next_run_at:
                schedule.next_run_at = compute_next_daily_run_at(
                    time_str=schedule.time or "02:00",
                    reference_utc=now,
                )
                initialized += 1
                continue
            if schedule.next_run_at <= now and schedule.device:
                due_tenant_ids.add(str(schedule.device.tenant_id))

        excluded_type_ids = resolve_mass_backup_excluded_type_ids(db)
        queued_devices = 0
        queued_direct = 0
        queued_jump = 0
        queued_vpn_groups = 0
        tenant_batches = 0

        for tenant_id in sorted(due_tenant_ids):
            tenant_uuid = tenant_id
            try:
                import uuid as _uuid
                tenant_uuid = _uuid.UUID(str(tenant_id))
            except Exception:
                tenant_uuid = tenant_id
            tenant_schedule_rows = [
                row for row in schedule_rows
                if row.device and str(row.device.tenant_id) == tenant_id
            ]
            tenant_time = _tenant_daily_time(tenant_id)
            tenant_devices = (
                db.query(Device)
                .options(joinedload(Device.group))
                .outerjoin(DeviceGroup, Device.group_id == DeviceGroup.id)
                .filter(Device.tenant_id == tenant_uuid, *active_device_filters)
                .all()
            )

            eligible_devices = []
            for device in tenant_devices:
                if excluded_type_ids and getattr(device, "device_type_id", None) in excluded_type_ids:
                    continue
                eligible_devices.append(device)

            due_vpn_by_group = defaultdict(lambda: {"tenant_id": tenant_id, "device_ids": []})
            due_jump_devices = []
            due_direct_devices = []

            for device in eligible_devices:
                if device.group and uses_vpn_tunnel(device.group, device=device):
                    entry = due_vpn_by_group[str(device.group_id)]
                    entry["tenant_id"] = tenant_id
                    entry["device_ids"].append(str(device.id))
                elif device.group and uses_jump_host(device.group, device=device):
                    # Guarda o objeto device para resolver o bastion na intercalacao.
                    due_jump_devices.append(device)
                else:
                    due_direct_devices.append(str(device.id))

            for idx, device_id in enumerate(due_direct_devices):
                run_backup_task.apply_async(args=[device_id], countdown=idx * 2)
                queued_direct += 1

            # Jump Host: round-robin por bastion + stagger por bastion. Maximiza o
            # paralelismo entre bastions distintos (velocidade) sem despejar varias
            # sessoes SSH simultaneas no mesmo bastion (estabilidade/anti-saturacao).
            for device, countdown in _interleave_by_bastion(due_jump_devices, _bastion_key_for_device):
                run_backup_task.apply_async(
                    args=[str(device.id)], queue="jump_queue", countdown=countdown
                )
                queued_jump += 1

            for group_id, data in due_vpn_by_group.items():
                unique_device_ids = sorted(set(data["device_ids"]))
                if not unique_device_ids:
                    continue
                run_vpn_group_backups_task.apply_async(
                    args=[group_id, data["tenant_id"], unique_device_ids],
                    queue="vpn_queue",
                )
                queued_vpn_groups += 1

            queued_devices += len(eligible_devices)
            tenant_batches += 1

            next_run = compute_next_daily_run_at(time_str=tenant_time, reference_utc=now + timedelta(seconds=1))
            for schedule in tenant_schedule_rows:
                schedule.frequency = ScheduleFrequency.DAILY
                schedule.time = tenant_time
                schedule.day_of_week = None
                schedule.day_of_month = None
                schedule.last_run_at = now
                schedule.next_run_at = next_run

        db.commit()

        if queued_devices > 0 or initialized > 0:
            logger.info(
                "Agendamento automatico por tenant: schedules=%s tenants_due=%s dispositivos=%s inicializados=%s",
                len(schedule_rows),
                len(due_tenant_ids),
                queued_devices,
                initialized,
            )
        return {
            'schedules_checked': len(schedule_rows),
            'tenant_batches_queued': tenant_batches,
            'devices_queued': queued_devices,
            'direct_devices_queued': queued_direct,
            'jump_devices_queued': queued_jump,
            'vpn_groups_queued': queued_vpn_groups,
            'initialized_next_run': initialized,
            'skipped_not_ready': 0,
        }
    finally:
        db.close()


@celery_app.task
def purge_expired_backups():
    """
    Remove backups expirados de acordo com a politica de retencao do plano.
    Backups de dispositivos ou grupos inativos sao preservados indefinidamente.
    """
    from app.models.backup import Backup
    from app.models.device import Device
    from app.models.tenant import Tenant
    from app.models.device_group import DeviceGroup
    from sqlalchemy import or_

    db = SessionLocal()

    try:
        tenants = db.query(Tenant).filter(Tenant.is_active == True).all()
        total_deleted = 0
        total_files_removed = 0

        for tenant in tenants:
            retention_days = settings.DEFAULT_RETENTION_DAYS
            if tenant.plan and tenant.plan.backup_retention_days:
                retention_days = tenant.plan.backup_retention_days

            cutoff = datetime.utcnow() - timedelta(days=retention_days)
            
            # Filtra apenas backups antigos de devices/grupos ATIVOS.
            # Se o device ou o grupo dele for inativo, preserva infinitamente.
            expired = db.query(Backup).join(Device).outerjoin(
                DeviceGroup, Device.group_id == DeviceGroup.id
            ).filter(
                Device.tenant_id == tenant.id,
                Backup.created_at < cutoff,
                Device.is_active == True,
                or_(Device.group_id.is_(None), DeviceGroup.is_active == True)
            ).all()

            for backup in expired:
                if backup.file_path and os.path.exists(backup.file_path):
                    try:
                        os.remove(backup.file_path)
                        total_files_removed += 1
                    except OSError:
                        logger.warning(f"Falha ao remover arquivo: {backup.file_path}")
                db.delete(backup)
                total_deleted += 1

            db.commit()

        logger.info(f"Retencao aplicada: {total_deleted} backups removidos, {total_files_removed} arquivos deletados.")
        return {'deleted': total_deleted, 'files_removed': total_files_removed}
    finally:
        db.close()


@celery_app.task
def purge_failed_backups_periodic():
    """
    Limpeza periódica de backups com status failed.
    Remove registros com mais de 3 dias para reduzir volume operacional.
    """
    from app.models.backup import Backup, BackupStatus
    from app.models.device import Device

    db = SessionLocal()
    cutoff = datetime.utcnow() - timedelta(days=3)
    storage_base = '/app/storage/backups'
    deleted = 0
    files_removed = 0

    try:
        failed_backups = (
            db.query(Backup)
            .join(Device)
            .filter(
                Backup.status == BackupStatus.FAILED,
                Backup.created_at < cutoff,
            )
            .all()
        )

        for backup in failed_backups:
            file_path = (backup.file_path or "").strip()
            absolute_path = None
            if file_path:
                absolute_path = file_path if os.path.isabs(file_path) else os.path.join(storage_base, file_path)
            if absolute_path and os.path.exists(absolute_path):
                try:
                    os.remove(absolute_path)
                    files_removed += 1
                except OSError:
                    logger.warning("Falha ao remover arquivo de backup failed (periodico): %s", absolute_path)
            db.delete(backup)
            deleted += 1

        db.commit()
        logger.info(
            "Limpeza periodica de backups failed concluida: removidos=%s arquivos=%s cutoff=%s",
            deleted,
            files_removed,
            cutoff.isoformat(),
        )
        return {"deleted": deleted, "files_removed": files_removed}
    finally:
        db.close()


@celery_app.task
def purge_activity_logs_periodic():
    """
    Limpeza periódica de logs de atividade (auditoria).
    Retenção padrão: 7 dias (configurável por ACTIVITY_LOG_RETENTION_DAYS).
    """
    db = SessionLocal()
    retention_days = max(int(getattr(settings, "ACTIVITY_LOG_RETENTION_DAYS", 7) or 7), 1)
    try:
        removed = ActivityService.prune_old_logs(db, retention_days=retention_days, dry_run=False)
        logger.info(
            "Limpeza periodica de activity logs concluida: removidos=%s retention_days=%s",
            removed,
            retention_days,
        )
        return {"removed": int(removed or 0), "retention_days": retention_days}
    finally:
        db.close()

from flask import Blueprint, render_template, redirect, url_for, request, flash, session, abort, jsonify
from app.web.auth.decorators import login_required, tenant_admin_required
from app.core.database import SessionLocal
from app.services.device_service import DeviceService, DeviceTypeService, DeviceGroupService
from app.services.device_subgroup_service import DeviceSubgroupService
from app.models.tenant import Tenant
from app.models.device import Device
from app.models.device_type import DeviceType
from app.models.device_group import DeviceGroup
from app.models.device_subgroup import DeviceSubgroup
from app.models.backup import Backup, BackupStatus
from app.models.user import User, UserRole
from app.services.connection_mode import uses_jump_host, uses_vpn_tunnel, get_effective_connection_type
from app.services.connection_test_service import connection_test_service
from app.services.mass_backup_scope import resolve_mass_backup_excluded_type_ids
from app.tasks.monitoring import run_connection_test_task, run_device_connection_audit_task
from celery.exceptions import TimeoutError as CeleryTimeoutError
from sqlalchemy.orm import joinedload
from sqlalchemy import or_
from app.core.security import decrypt_password
import uuid
import logging
import os
from datetime import datetime, timezone, timedelta

bp = Blueprint('tenant_devices', __name__, url_prefix='/tenant/<tenant_slug>/devices')
JUMP_HOST_COUNTDOWN_STEP_SECONDS = 8
DIRECT_GLOBAL_BATCH_SIZE = 25

_BUILTIN_DEVICE_FIELDS = {
    "username",
    "password",
    "ip_address",
    "host",
    "hostname",
    "port",
    "use_telnet",
}
MASS_BACKUP_EXCLUDED_TYPE_LABEL = "Grafana/Zabbix"
SUBGROUP_CONNECTION_TYPE_KEY = "connection_subgroup_type"
SUBGROUP_CONNECTION_ENABLED_KEY = "connection_subgroup_enabled"
SUBGROUP_CONNECTION_UPDATED_AT_KEY = "connection_subgroup_updated_at"
VALID_SUBGROUP_CONNECTION_TYPES = {"direct", "vpn", "jump_host"}
ZABBIX_SCRIPT_NAME = "zabbix_backup.py"
ZABBIX_DB_CONF_PATH = "/etc/zabbix/zabbix_server.conf"
ZABBIX_AUTODISCOVERY_MODE_KEY = "db_credentials_mode"
ZABBIX_AUTODISCOVERY_MODE_MANUAL = "manual"
ZABBIX_AUTODISCOVERY_MODE_AUTOMATIC = "automatic"
ZABBIX_DB_EXTRA_FIELDS = ("db_name", "db_user", "db_password")
ZABBIX_DEFAULT_EXCLUDE_TABLES = (
    "history,history_uint,history_str,history_log,history_text,trends,trends_uint"
)


def _normalize_zabbix_db_type(raw_value) -> str:
    raw = str(raw_value or "").strip().lower()
    if raw in {"postgres", "postgresql", "postgre", "postgree", "pgsql"}:
        return "postgres"
    if raw in {"mariadb", "mysql"}:
        return "mariadb"
    return "postgres"


def _can_view_saved_credentials(db=None) -> bool:
    role = session.get('user_role')
    if role == UserRole.TENANT_OWNER.value:
        return True

    if db is None:
        return False

    raw_user_id = session.get('user_id')
    if not raw_user_id:
        return False

    try:
        user_uuid = uuid.UUID(str(raw_user_id))
    except (TypeError, ValueError):
        return False

    user = db.query(User).filter(User.id == user_uuid, User.is_active.is_(True)).first()
    if not user:
        return False

    current_role = getattr(user.role, 'value', user.role)
    if current_role and current_role != role:
        session['user_role'] = current_role

    return current_role == UserRole.TENANT_OWNER.value


def _safe_decrypt_secret(encrypted_value, *, context_label: str, entity_id) -> str | None:
    if not encrypted_value:
        return None
    try:
        return decrypt_password(encrypted_value)
    except Exception:
        logging.getLogger(__name__).warning(
            "Falha ao descriptografar segredo salvo em %s para entidade %s",
            context_label,
            entity_id,
            exc_info=True,
        )
        return None


def _current_saved_secret_if_owner(db, encrypted_value, *, context_label: str, entity_id) -> str | None:
    if not _can_view_saved_credentials(db):
        return None
    return _safe_decrypt_secret(
        encrypted_value,
        context_label=context_label,
        entity_id=entity_id,
    )


def _parse_group_uuid(raw_value):
    if not raw_value:
        return None
    try:
        return uuid.UUID(str(raw_value))
    except (TypeError, ValueError):
        return None


def _parse_required_parameters(raw):
    if raw is None:
        return []
    values = []
    for line in str(raw).replace(',', '\n').splitlines():
        item = line.strip()
        if item and item not in values:
            values.append(item)
    return values


def _is_sensitive_parameter(name: str) -> bool:
    value = (name or "").strip().lower()
    return any(token in value for token in ("password", "secret", "token", "key"))


def _build_device_type_metadata(device_types):
    metadata = {}
    for dev_type in device_types or []:
        metadata[str(dev_type.id)] = {
            "required_parameters": _parse_required_parameters(dev_type.required_parameters),
            "default_port": dev_type.default_port or 22,
            "use_telnet": bool(dev_type.use_telnet),
            "script_name": dev_type.script_name or "",
        }
    return metadata


def _script_name_for_device_type(device_type) -> str:
    return str(getattr(device_type, "script_name", "") or "").strip().lower()


def _is_zabbix_device_type(device_type) -> bool:
    return _script_name_for_device_type(device_type) == ZABBIX_SCRIPT_NAME


def _normalize_zabbix_credentials_mode(raw_value) -> str:
    mode = str(raw_value or "").strip().lower()
    if mode == ZABBIX_AUTODISCOVERY_MODE_AUTOMATIC:
        return ZABBIX_AUTODISCOVERY_MODE_AUTOMATIC
    return ZABBIX_AUTODISCOVERY_MODE_MANUAL


def _parse_zabbix_db_config(output: str) -> dict:
    parsed = {}
    for raw_line in str(output or "").splitlines():
        line = str(raw_line or "").strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key not in {"DBName", "DBUser", "DBPassword"}:
            continue
        if (
            (value.startswith('"') and value.endswith('"'))
            or (value.startswith("'") and value.endswith("'"))
        ):
            value = value[1:-1]
        parsed[key] = value
    return parsed


def _discover_zabbix_db_params_ssh(host: str, port: int, username: str, password: str, logger=None) -> dict:
    from netmiko import ConnectHandler

    device_config = {
        "device_type": "linux",
        "host": host,
        "port": int(port),
        "username": username,
        "password": password,
        "conn_timeout": 35,
        "banner_timeout": 35,
        "auth_timeout": 35,
        "fast_cli": False,
    }
    commands = [
        f"grep -E '^(DB(Name|User|Password))=' {ZABBIX_DB_CONF_PATH} 2>/dev/null",
        f"sudo grep -E '^(DB(Name|User|Password))=' {ZABBIX_DB_CONF_PATH} 2>/dev/null",
        f"sudo -n grep -E '^(DB(Name|User|Password))=' {ZABBIX_DB_CONF_PATH} 2>/dev/null",
    ]
    with ConnectHandler(**device_config) as net_connect:
        if hasattr(net_connect, "is_alive") and not net_connect.is_alive():
            raise RuntimeError("Conexao SSH estabelecida, mas sessao nao permaneceu ativa.")
        probe = net_connect.send_command_timing(
            "echo __BC_ZABBIX_AUTODISCOVERY_OK__",
            read_timeout=15,
            strip_command=False,
            strip_prompt=False,
        )
        if "__BC_ZABBIX_AUTODISCOVERY_OK__" not in str(probe or ""):
            raise RuntimeError("Conexao SSH valida, mas shell remoto nao respondeu conforme esperado.")

        parsed = {}
        for command in commands:
            output = net_connect.send_command_timing(
                command,
                read_timeout=20,
                strip_command=False,
                strip_prompt=False,
            )
            parsed = _parse_zabbix_db_config(output)
            if parsed:
                break
        if not parsed:
            raise RuntimeError(
                (
                    f"Nao foi possivel ler DBName/DBUser/DBPassword em {ZABBIX_DB_CONF_PATH}. "
                    "Valide permissao de leitura e conteudo do arquivo."
                )
            )
        return parsed


def _collect_device_extra_parameters(form, device_type, existing_extra=None):
    extra = dict(existing_extra or {})
    selected_params = _parse_required_parameters(getattr(device_type, "required_parameters", None))
    is_zabbix = _is_zabbix_device_type(device_type)
    zabbix_mode = _normalize_zabbix_credentials_mode(
        form.get(f"extra__{ZABBIX_AUTODISCOVERY_MODE_KEY}")
    ) if is_zabbix else None

    if is_zabbix:
        extra[ZABBIX_AUTODISCOVERY_MODE_KEY] = zabbix_mode

    for param_name in selected_params:
        if param_name in _BUILTIN_DEVICE_FIELDS:
            continue
        field_name = f"extra__{param_name}"
        raw_value = form.get(field_name)
        value = (raw_value or "").strip()
        if value:
            extra[param_name] = value
            continue
        if is_zabbix and param_name in ZABBIX_DB_EXTRA_FIELDS:
            # Protecao para producao: nao remove credenciais DB existentes
            # quando os campos vierem vazios no formulario.
            continue
        if _is_sensitive_parameter(param_name) and param_name in extra:
            continue
        extra.pop(param_name, None)

    if is_zabbix:
        db_type_value = _normalize_zabbix_db_type(form.get("extra__db_type") or extra.get("db_type"))
        extra["db_type"] = db_type_value

        exclude_value = str(form.get("extra__exclude_tables") or extra.get("exclude_tables") or "").strip()
        if not exclude_value:
            exclude_value = ZABBIX_DEFAULT_EXCLUDE_TABLES
        extra["exclude_tables"] = exclude_value

    return extra


def get_db_and_tenant(tenant_slug):
    # Cross-tenant check
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)
        
    db = SessionLocal()
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
    if not tenant:
        db.close()
    return db, tenant


def _resolve_group_context(db, tenant_id, raw_group_id):
    group_uuid = _parse_group_uuid(raw_group_id)
    if not group_uuid:
        return None
    group = DeviceGroupService.get_group(db, group_uuid)
    if not group or str(group.tenant_id) != str(tenant_id):
        return None
    return group


def _group_id_str(group):
    if not group:
        return None
    try:
        return str(group.id)
    except Exception:
        return None


def _normalize_connection_type(raw_value: str | None) -> str:
    raw = str(raw_value or "").strip().lower()
    if raw in {"jump", "jump_host"}:
        return "jump_host"
    if raw in {"direct", "vpn"}:
        return raw
    return ""


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "on", "yes", "sim"}


def _device_subgroup_connection_type(device) -> str:
    subgroup = getattr(device, "subgroup", None)
    if subgroup and bool(getattr(subgroup, "is_active", True)):
        conn = _normalize_connection_type(getattr(subgroup, "connection_type", None))
        if conn:
            return conn

    extra = dict(getattr(device, "extra_parameters", None) or {})
    if not extra:
        return ""
    conn = _normalize_connection_type(
        extra.get(SUBGROUP_CONNECTION_TYPE_KEY) or extra.get("subgroup_connection_type")
    )
    enabled = _truthy(
        extra.get(SUBGROUP_CONNECTION_ENABLED_KEY)
        if SUBGROUP_CONNECTION_ENABLED_KEY in extra
        else extra.get("subgroup_connection_enabled")
    )
    if conn and (enabled or SUBGROUP_CONNECTION_TYPE_KEY in extra or "subgroup_connection_type" in extra):
        return conn
    return ""


def _resolve_enqueue_throttle(device):
    """
    Retorna (throttle_key, step_seconds) para suavizar enfileiramento.
    - Jump host: serializa por bastion (host:porta).
    - Direto: mantém suavização global em lotes.
    """
    group = getattr(device, "group", None)
    if group and uses_jump_host(group, device=device) and getattr(group, "jump_host", None):
        host = str(getattr(group, "jump_host", "") or "").strip().lower()
        port = int(getattr(group, "jump_port", 22) or 22)
        return f"jump:{host}:{port}", JUMP_HOST_COUNTDOWN_STEP_SECONDS
    return "direct:global", 0


def _next_countdown_for_device(device, throttle_counters):
    key, step_seconds = _resolve_enqueue_throttle(device)
    slot = int(throttle_counters.get(key, 0))
    throttle_counters[key] = slot + 1
    if step_seconds > 0:
        return slot * step_seconds
    return slot // DIRECT_GLOBAL_BATCH_SIZE


def _backup_queue_for_device(device) -> str:
    group = getattr(device, "group", None)
    if group and uses_vpn_tunnel(group, device=device):
        return "vpn_queue"
    return "celery"


def _append_group_phase_bucket(bucket: dict, device, *, force_vpn: bool = False):
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


def _finalize_group_phase_payload(bucket: dict):
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


def _split_mass_backup_devices(devices, excluded_type_ids):
    allowed = []
    excluded = []
    for device in devices or []:
        if getattr(device, "device_type_id", None) in excluded_type_ids:
            excluded.append(device)
            continue
        allowed.append(device)
    return allowed, excluded


def _env_bool(name: str, default: str = "0") -> bool:
    return str(os.getenv(name, default) or "").strip().lower() in {"1", "true", "on", "yes"}


def _value_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    return str(value).strip().lower() in {"1", "true", "on", "yes", "sim"}


def _merge_existing_bulk_children(bulk_task_id, child_task_ids, child_task_device_count, total_tasks):
    if not bulk_task_id:
        return child_task_ids, child_task_device_count, total_tasks
    from app.services.realtime_backup_logs import get_task_meta

    current = get_task_meta(str(bulk_task_id)) or {}
    existing_ids = [str(tid) for tid in (current.get("child_task_ids") or []) if tid]
    merged_ids = list(dict.fromkeys([str(tid) for tid in (child_task_ids or []) if tid] + existing_ids))

    merged_counts = dict(current.get("child_task_device_count") or {})
    merged_counts.update({str(k): int(v) for k, v in (child_task_device_count or {}).items()})

    merged_total = max(int(total_tasks or 0), int(current.get("total_tasks") or 0), len(merged_ids))
    return merged_ids, merged_counts, merged_total


def _reserve_bulk_or_json_error(tenant_id, bulk_task_id):
    from app.services.realtime_backup_logs import acquire_tenant_bulk_lock

    ok, existing_task_id = acquire_tenant_bulk_lock(str(tenant_id), str(bulk_task_id))
    if ok:
        return None
    return jsonify({
        "ok": False,
        "error": (
            "Ja existe um lote de backup em andamento para este tenant. "
            "Aguarde finalizar ou use Parar lote/Parar todos antes de iniciar outro."
        ),
        "active_task_id": existing_task_id,
    }), 409


def _env_int(name: str, default: int, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        value = int(str(os.getenv(name, str(default))).strip())
    except Exception:
        value = int(default)
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _bulk_preflight_filter_devices(
    devices,
    tenant_id: str,
    bulk_task_id: str | None = None,
    include_unvalidated: bool = False,
    enqueue_audit: bool = False,
):
    from app.services.backup_diagnostics import is_connection_ready_recent
    from app.services.backup_observability import inc_counter

    # POLITICA: TODO dispositivo marcado para backup automatico/agendado DEVE ter o backup
    # executado, independente do resultado de testes de conectividade anteriores. A logica
    # antiga de "pular dispositivos not-ready" foi removida: um device que falhou um teste no
    # passado (ICMP bloqueado, fora do ar momentaneo) ficava preso sendo ignorado no backup
    # em massa mesmo ja acessivel, enquanto o backup manual individual funcionava.
    #
    # Esta funcao agora NUNCA pula um dispositivo. Mantemos apenas:
    #  - telemetria de classificacao (observabilidade);
    #  - auditoria de conexao em paralelo (nao-bloqueante, so atualiza o status do device).
    max_age_minutes = _env_int("BULK_PREFLIGHT_MAX_AGE_MINUTES", 45, minimum=5, maximum=720)
    auto_audit = bool(enqueue_audit) and _env_bool("BULK_PREFLIGHT_AUTO_AUDIT", "1")
    auto_audit_limit = _env_int("BULK_PREFLIGHT_AUTO_AUDIT_LIMIT", 120, minimum=0, maximum=5000)

    all_devices = list(devices or [])
    counts = {}
    audit_queued = 0

    for device in all_devices:
        extra = dict(getattr(device, "extra_parameters", None) or {})
        ready_recent, _reason = is_connection_ready_recent(extra, max_age_minutes=max_age_minutes)
        test_group = str(extra.get("connection_test_group") or "").strip().lower()
        classification = "ready" if ready_recent else (test_group or "unknown")

        if classification not in counts:
            counts[classification] = 0
        counts[classification] += 1
        inc_counter(
            "bulk_preflight_devices_total",
            labels={
                "tenant_id": str(tenant_id),
                "classification": classification,
            },
        )

        # Auditoria paralela apenas para manter o status de conexao atualizado.
        # NAO impede nem adia o backup do dispositivo.
        if not ready_recent and auto_audit and audit_queued < auto_audit_limit:
            try:
                target_queue = "vpn_queue" if (
                    getattr(device, "group", None)
                    and uses_vpn_tunnel(device.group, device=device)
                ) else "celery"
                run_device_connection_audit_task.apply_async(
                    args=[str(device.id), bulk_task_id],
                    queue=target_queue,
                )
                audit_queued += 1
            except Exception:
                logging.getLogger(__name__).exception(
                    "Falha ao enfileirar auditoria automatica para %s",
                    getattr(device, "id", None),
                )

    return all_devices, {
        "enabled": True,
        "include_unvalidated": bool(include_unvalidated),
        "skipped_not_ready": 0,
        "audit_queued": audit_queued,
        "counts": counts,
    }


def _device_jump_endpoint(device):
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


def _format_jump_unreachable_summary(summary: dict | None, limit: int = 3) -> str:
    rows = list((summary or {}).get("unreachable_endpoints") or [])
    if not rows:
        return ""
    parts = []
    for row in rows[:max(1, int(limit or 1))]:
        endpoint = str(row.get("endpoint") or "desconhecido")
        devices = int(row.get("devices") or 0)
        method = str(row.get("tcp_method") or "").strip()
        suffix = f" via {method}" if method else ""
        parts.append(f"{endpoint} ({devices} disp.{suffix})")
    if len(rows) > len(parts):
        parts.append(f"+{len(rows) - len(parts)} endpoint(s)")
    return "; ".join(parts)


def _bulk_preflight_jump_hosts(
    devices,
    tenant_id: str,
):
    from app.services.network_precheck import run_network_precheck
    from app.services.backup_observability import inc_counter

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
        key, host, port = _device_jump_endpoint(device)
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
                "missing_host": not bool(host),
            }
            endpoint_map[key] = entry
        entry["devices"].append(device)
        group_name = str(getattr(getattr(device, "group", None), "name", "") or "").strip() or "Sem grupo"
        entry["group_names"].add(group_name)

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
        key, _host, _port = _device_jump_endpoint(device)
        if not key:
            allowed.append(device)
            continue
        result = endpoint_result.get(key) or {}
        tcp_ok = bool(result.get("tcp_ok", True))
        classification = "jump_host_ready" if tcp_ok else "jump_host_unreachable"
        inc_counter(
            "bulk_preflight_devices_total",
            labels={
                "tenant_id": str(tenant_id),
                "classification": classification,
            },
        )
        if (not tcp_ok) and skip_unreachable:
            skipped.append(device)
            continue
        allowed.append(device)

    return allowed, {
        "enabled": True,
        "timeout_seconds": timeout_seconds,
        "skip_unreachable": bool(skip_unreachable),
        "checked_endpoints": len(probe_keys),
        "total_endpoints": len(ordered_keys),
        "probe_truncated": bool(probe_truncated),
        "skipped_jump_unreachable": len(skipped),
        "skipped_device_ids": [str(getattr(device, "id", "")) for device in skipped if getattr(device, "id", None)],
        "unreachable_endpoints": unreachable_endpoints,
    }


def _clear_global_force_stop_flag() -> bool:
    """Remove a trava global de parada forcada quando o operador inicia novo backup manual."""
    try:
        from app.services.realtime_backup_logs import get_redis_client
        r = get_redis_client()
        if not r:
            return False
        key = "backup_center:force_stop_backups"
        had_flag = str(r.get(key) or "").strip() == "1"
        if had_flag:
            r.delete(key)
            logging.getLogger(__name__).warning("Flag global de stop removida para novo backup manual.")
        return had_flag
    except Exception:
        logging.getLogger(__name__).exception("Falha ao limpar flag global de stop")
        return False


@bp.route('/')
@login_required
def list_devices(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404
    try:
        # Filtro por grupo
        group_id = request.args.get('group_id')
        subgroup_filter_raw = (request.args.get('subgroup') or '').strip()
        search_query = request.args.get('q')
        connection_filter = (request.args.get('connection') or '').strip().lower() or None
        auto_filter = (request.args.get('auto') or '').strip().lower() or None
        result_filter = (request.args.get('result') or '').strip().lower() or None
        history_filter = (request.args.get('history') or '').strip().lower() or None
        connection_audit_filter = (request.args.get('audit') or '').strip().lower() or None
        due_filter = (request.args.get('due') or '').strip() or None
        compare_mode = (request.args.get('compare') or '').strip() == '1'
        sort_by = (request.args.get('sort') or 'name_asc').strip().lower()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 30, type=int)
        per_page = max(10, min(per_page, 100))

        if connection_filter not in {None, 'online', 'offline', 'unknown', 'direct', 'vpn', 'jump', 'jump_host'}:
            connection_filter = None
        if auto_filter not in {None, 'enabled', 'disabled'}:
            auto_filter = None
        if result_filter not in {None, 'success', 'failed', 'never'}:
            result_filter = None
        if history_filter not in {None, 'with_history', 'without_history'}:
            history_filter = None
        if connection_audit_filter not in {None, 'ping_ok', 'login_ok', 'ping_login_fail', 'no_ping'}:
            connection_audit_filter = None
        if due_filter not in {None, '1'}:
            due_filter = None
        if sort_by not in {'name_asc', 'name_desc', 'last_backup_desc', 'last_backup_asc', 'status_priority'}:
            sort_by = 'name_asc'

        group_id = _parse_group_uuid(group_id)
        subgroup_filter = None
        if subgroup_filter_raw:
            if subgroup_filter_raw.lower() in {"none", "__none__"}:
                subgroup_filter = "none"
                subgroup_filter_raw = "none"
            else:
                try:
                    subgroup_filter = uuid.UUID(subgroup_filter_raw)
                except (TypeError, ValueError):
                    subgroup_filter = None
                    subgroup_filter_raw = ""

        result = DeviceService.get_tenant_devices(
            db,
            tenant.id,
            group_id,
            subgroup_filter=subgroup_filter,
            search_query=search_query,
            connection_filter=connection_filter,
            auto_filter=auto_filter,
            backup_result_filter=result_filter,
            history_filter=history_filter,
            connection_audit_filter=connection_audit_filter,
            due_filter=due_filter,
            sort_by=sort_by,
            page=page,
            per_page=per_page,
        )
        devices = result["items"]
        groups = DeviceGroupService.get_groups_with_device_count(db, tenant.id)
        device_types = DeviceTypeService.get_types_by_category(db)

        stats = {
            "total": result["total"],
            "scheduled": result["scheduled"],
            "online": result["online"],
            "with_issues": result["with_issues"],
            "offline": result.get("offline", 0),
            "without_history": result.get("without_history", 0),
            "auto_disabled": result.get("auto_disabled", 0),
        }
        total_pages = (result["total"] + per_page - 1) // per_page
        start_idx = ((page - 1) * per_page) + 1 if result["total"] > 0 else 0
        end_idx = min(page * per_page, result["total"])

        current_group = _resolve_group_context(db, tenant.id, group_id)
        group_subgroups = []
        group_devices_for_subgroup = []
        subgroup_none_count = 0
        subgroup_total_count = 0
        if current_group:
            group_subgroups = DeviceSubgroupService.get_group_subgroups_with_count(
                db,
                tenant.id,
                current_group.id,
            )
            group_devices_for_subgroup = (
                db.query(Device)
                .options(joinedload(Device.type), joinedload(Device.subgroup))
                .filter(
                    Device.tenant_id == tenant.id,
                    Device.group_id == current_group.id,
                    Device.is_active.isnot(False),
                )
                .order_by(Device.name.asc())
                .all()
            )
            subgroup_total_count = len(group_devices_for_subgroup)
            subgroup_none_count = sum(
                1 for d in group_devices_for_subgroup if getattr(d, "subgroup_id", None) is None
            )

        return render_template(
            'tenant/devices/list.html',
            tenant=tenant,
            devices=devices,
            groups=groups,
            device_types=device_types,
            stats=stats,
            current_group=current_group,
            group_subgroups=group_subgroups,
            group_devices_for_subgroup=group_devices_for_subgroup,
            current_subgroup_filter=subgroup_filter_raw,
            subgroup_none_count=subgroup_none_count,
            subgroup_total_count=subgroup_total_count,
            page=page,
            per_page=per_page,
            total_pages=total_pages,
            start_idx=start_idx,
            end_idx=end_idx,
            current_connection_filter=connection_filter,
            current_auto_filter=auto_filter,
            current_result_filter=result_filter,
            current_history_filter=history_filter,
            current_connection_audit_filter=connection_audit_filter,
            current_due_filter=due_filter,
            current_sort=sort_by,
            compare_mode=compare_mode,
        )
    finally:
        db.close()

@bp.route('/add', methods=['GET', 'POST'])
@login_required
@tenant_admin_required
def add_device(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    groups = DeviceGroupService.get_tenant_groups(db, tenant.id)
    device_types = DeviceTypeService.get_all_types(db)
    type_metadata = _build_device_type_metadata(device_types)
    
    if request.method == 'POST':
        try:
            raw_group_id = (request.form.get('group_id') or '').strip()
            selected_group = _resolve_group_context(db, tenant.id, raw_group_id)
            if not selected_group or not bool(getattr(selected_group, 'is_active', True)):
                raise ValueError('Selecione um grupo ativo para cadastrar o dispositivo.')

            device_type_id = request.form.get('device_type_id') or None
            selected_type = None
            if device_type_id:
                selected_type = DeviceTypeService.get_type(db, uuid.UUID(device_type_id))
            data = {
                'name': request.form.get('name'),
                'device_type_id': device_type_id,
                'group_id': selected_group.id,
                'ip_address': request.form.get('ip_address'),
                'port': int(request.form.get('port', 22)),
                'username': request.form.get('username'),
                'password': request.form.get('password'),
                'description': request.form.get('description'),
                'use_telnet': request.form.get('use_telnet') == 'on',
                'backup_scheduled': request.form.get('backup_scheduled') == 'on',  # Checkbox value
                'extra_parameters': _collect_device_extra_parameters(request.form, selected_type),
            }
            device = DeviceService.create_device(db, tenant.id, data)
            
            # LOG ACTIVITY: Create Device
            from app.services.activity_service import ActivityService
            user_id = session.get('user_id')
            ActivityService.log_action(db, tenant.id, user_id, "CREATE_DEVICE", f"Created device: {device.name} ({device.ip_address})", request.remote_addr)

            flash('Dispositivo adicionado com sucesso!', 'success')
            return redirect(url_for('tenant_devices.list_devices', tenant_slug=tenant_slug))
        except Exception as e:
            flash(f'Erro ao adicionar dispositivo: {str(e)}', 'error')
    
    response = render_template(
        'tenant/devices/add.html',
        tenant=tenant,
        groups=groups,
        device_types=device_types,
        type_metadata=type_metadata,
    )
    db.close()
    return response


@bp.route('/zabbix/autodiscover-db', methods=['POST'])
@login_required
@tenant_admin_required
def zabbix_autodiscover_db(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return jsonify({"ok": False, "error": "Tenant nao encontrado."}), 404

    try:
        payload = request.get_json(silent=True) or request.form

        raw_device_type_id = str((payload.get("device_type_id") or "")).strip()
        if not raw_device_type_id:
            return jsonify({"ok": False, "error": "Selecione o tipo de equipamento."}), 400
        try:
            device_type_uuid = uuid.UUID(raw_device_type_id)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Tipo de equipamento invalido."}), 400
        device_type = DeviceTypeService.get_type(db, device_type_uuid)
        if not device_type:
            return jsonify({"ok": False, "error": "Tipo de equipamento nao encontrado."}), 404
        if not _is_zabbix_device_type(device_type):
            return jsonify({"ok": False, "error": "Autodeteccao disponivel apenas para Zabbix."}), 400

        host = str((payload.get("ip_address") or "")).strip()
        username = str((payload.get("username") or "")).strip()
        raw_port = str((payload.get("port") or "22")).strip()
        raw_password = str((payload.get("password") or "")).strip()
        raw_device_id = str((payload.get("device_id") or "")).strip()

        if not host:
            return jsonify({"ok": False, "error": "Informe o IP/host do servidor Zabbix."}), 400
        if not username:
            return jsonify({"ok": False, "error": "Informe o usuario SSH do servidor Zabbix."}), 400
        try:
            port = int(raw_port or 22)
        except Exception:
            return jsonify({"ok": False, "error": "Porta invalida."}), 400

        password = raw_password
        if not password and raw_device_id:
            try:
                device_uuid = uuid.UUID(raw_device_id)
                existing_device = DeviceService.get_device(db, device_uuid)
                if (
                    existing_device
                    and str(getattr(existing_device, "tenant_id", "")) == str(tenant.id)
                    and str(getattr(existing_device, "ip_address", "") or "").strip() == host
                    and str(getattr(existing_device, "username", "") or "").strip() == username
                    and int(getattr(existing_device, "port", 22) or 22) == port
                ):
                    password = _safe_decrypt_secret(
                        getattr(existing_device, "password_encrypted", None),
                        context_label="tenant_devices.zabbix_autodiscover_db.device_password",
                        entity_id=existing_device.id,
                    ) or ""
            except Exception:
                password = ""
        if not password:
            return jsonify(
                {
                    "ok": False,
                    "error": (
                        "Informe a senha SSH para validar conexao antes da autodeteccao "
                        "ou mantenha host/usuario/porta iguais ao cadastro atual."
                    ),
                }
            ), 400

        discovered = _discover_zabbix_db_params_ssh(
            host=host,
            port=port,
            username=username,
            password=password,
        )

        db_name = str(discovered.get("DBName") or "").strip()
        db_user = str(discovered.get("DBUser") or "").strip()
        db_password = str(discovered.get("DBPassword") or "").strip()
        if not db_name or not db_user or not db_password:
            return jsonify(
                {
                    "ok": False,
                    "error": (
                        f"Conexao SSH validada, mas faltam campos DB em {ZABBIX_DB_CONF_PATH} "
                        "(DBName/DBUser/DBPassword)."
                    ),
                }
            ), 400

        return jsonify(
            {
                "ok": True,
                "message": "Conexao validada e parametros DB detectados com sucesso.",
                "data": {
                    "db_type": "postgres",
                    "db_name": db_name,
                    "db_user": db_user,
                    "db_password": db_password,
                    "exclude_tables": ZABBIX_DEFAULT_EXCLUDE_TABLES,
                    ZABBIX_AUTODISCOVERY_MODE_KEY: ZABBIX_AUTODISCOVERY_MODE_AUTOMATIC,
                },
            }
        )
    except Exception as e:
        return jsonify({"ok": False, "error": f"Falha ao validar/buscar parametros: {e}"}), 500
    finally:
        db.close()


@bp.route('/<device_id>')
@login_required
def view_device(tenant_slug, device_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404
    
    try:
        device_uuid = uuid.UUID(device_id)
    except ValueError:
        return "Invalid device ID", 400
    
    device = DeviceService.get_device(db, device_uuid)
    if not device or str(device.tenant_id) != str(tenant.id):
        db.close()
        return "Device not found", 404

    return_group = _resolve_group_context(
        db,
        tenant.id,
        request.args.get('group_id') or request.args.get('return_group_id') or device.group_id,
    )
    
    # Historico de backups com paginacao (nao limitar em 10 fixo)
    from app.models.backup import Backup
    backup_page = request.args.get('backup_page', 1, type=int) or 1
    if backup_page < 1:
        backup_page = 1
    backup_per_page = 25

    backup_query = db.query(Backup).filter(Backup.device_id == device.id)
    backups_total = int(backup_query.count() or 0)
    backup_total_pages = max(1, (backups_total + backup_per_page - 1) // backup_per_page)
    if backup_page > backup_total_pages:
        backup_page = backup_total_pages

    backups = (
        backup_query
        .order_by(Backup.created_at.desc())
        .offset((backup_page - 1) * backup_per_page)
        .limit(backup_per_page)
        .all()
    )
    
    db.close()
    return render_template(
        'tenant/devices/view.html',
        tenant=tenant,
        device=device,
        backups=backups,
        backups_total=backups_total,
        backup_page=backup_page,
        backup_total_pages=backup_total_pages,
        backup_per_page=backup_per_page,
        return_group=return_group,
    )


@bp.route('/<device_id>/edit', methods=['GET', 'POST'])
@login_required
@tenant_admin_required
def edit_device(tenant_slug, device_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404
    
    try:
        device_uuid = uuid.UUID(device_id)
    except ValueError:
        return "Invalid device ID", 400
    
    device = DeviceService.get_device(db, device_uuid)
    if not device or str(device.tenant_id) != str(tenant.id):
        db.close()
        return "Device not found", 404

    return_group = _resolve_group_context(
        db,
        tenant.id,
        request.args.get('group_id') or request.args.get('return_group_id') or request.form.get('return_group_id') or device.group_id,
    )
    return_group_id = _group_id_str(return_group)
    
    if request.method == 'POST':
        try:
            device_type_id = request.form.get('device_type_id') or None
            selected_type = None
            if device_type_id:
                selected_type = DeviceTypeService.get_type(db, uuid.UUID(device_type_id))
            current_password = _current_saved_secret_if_owner(
                db,
                getattr(device, 'password_encrypted', None),
                context_label='tenant_devices.edit_device.password',
                entity_id=device.id,
            )
            data = {
                'name': request.form.get('name'),
                'device_type_id': device_type_id,
                'group_id': _parse_group_uuid(request.form.get('group_id')) or None,
                'ip_address': request.form.get('ip_address'),
                'port': int(request.form.get('port', 22)),
                'username': request.form.get('username'),
                'description': request.form.get('description'),
                'use_telnet': request.form.get('use_telnet') == 'on',
                'backup_scheduled': request.form.get('backup_scheduled') == 'on',
                'extra_parameters': _collect_device_extra_parameters(
                    request.form,
                    selected_type,
                    existing_extra=device.extra_parameters,
                ),
            }
            # Só atualiza senha se foi fornecida
            password = request.form.get('password')
            if password and password != current_password:
                data['password'] = password
            
            DeviceService.update_device(db, device_uuid, data)
            
            # LOG ACTIVITY: Update Device
            from app.services.activity_service import ActivityService
            user_id = session.get('user_id')
            ActivityService.log_action(db, tenant.id, user_id, "UPDATE_DEVICE", f"Updated device: {device.name}", request.remote_addr)

            flash('Dispositivo atualizado com sucesso!', 'success')
            return redirect(url_for(
                'tenant_devices.view_device',
                tenant_slug=tenant_slug,
                device_id=device_id,
                group_id=return_group_id,
            ))
        except Exception as e:
            flash(f'Erro ao atualizar dispositivo: {str(e)}', 'error')
    
    groups = DeviceGroupService.get_tenant_groups(db, tenant.id)
    device_types = DeviceTypeService.get_all_types(db)
    type_metadata = _build_device_type_metadata(device_types)
    can_view_saved_credentials = _can_view_saved_credentials(db)
    device_current_password = None
    if can_view_saved_credentials:
        device_current_password = _safe_decrypt_secret(
            getattr(device, 'password_encrypted', None),
            context_label='tenant_devices.edit_device.password',
            entity_id=device.id,
        )
    
    response = render_template(
        'tenant/devices/edit.html',
        tenant=tenant,
        device=device,
        groups=groups,
        device_types=device_types,
        type_metadata=type_metadata,
        device_extra_parameters=device.extra_parameters or {},
        return_group=return_group,
        can_view_saved_credentials=can_view_saved_credentials,
        device_current_password=device_current_password,
    )
    db.close()
    return response


@bp.route('/<device_id>/delete', methods=['POST'])
@login_required
@tenant_admin_required
def delete_device(tenant_slug, device_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404
    
    try:
        device_uuid = uuid.UUID(device_id)
    except ValueError:
        flash('ID de dispositivo inválido', 'error')
        return redirect(url_for('tenant_devices.list_devices', tenant_slug=tenant_slug))

    return_group = _resolve_group_context(
        db,
        tenant.id,
        request.form.get('return_group_id') or request.args.get('group_id') or request.args.get('return_group_id'),
    )
    
    # Busca nome antes de deletar para log
    device = db.query(Device).filter(
        Device.id == device_uuid,
        Device.tenant_id == tenant.id,
    ).first()
    device_name = device.name if device else "Unknown"
    if not return_group and device and device.group_id:
        return_group = _resolve_group_context(db, tenant.id, device.group_id)
    return_group_id = _group_id_str(return_group)

    if DeviceService.delete_device(db, device_uuid):
        # LOG ACTIVITY: Delete Device
        from app.services.activity_service import ActivityService
        user_id = session.get('user_id')
        ActivityService.log_action(db, tenant.id, user_id, "DELETE_DEVICE", f"Deleted device: {device_name}", request.remote_addr)

        flash('Dispositivo removido com sucesso!', 'success')
    else:
        flash('Erro ao remover dispositivo', 'error')
    
    db.close()
    return redirect(url_for(
        'tenant_devices.list_devices',
        tenant_slug=tenant_slug,
        group_id=return_group_id,
    ))


@bp.route('/<device_id>/clear-backup-error', methods=['POST'])
@login_required
@tenant_admin_required
def clear_backup_error(tenant_slug, device_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    try:
        device_uuid = uuid.UUID(device_id)
    except ValueError:
        flash('ID de dispositivo inválido.', 'error')
        return redirect(url_for('tenant_devices.list_devices', tenant_slug=tenant_slug))

    device = DeviceService.get_device(db, device_uuid)
    if not device or str(device.tenant_id) != str(tenant.id):
        db.close()
        return "Device not found", 404

    return_group = _resolve_group_context(
        db,
        tenant.id,
        request.form.get('return_group_id') or request.args.get('group_id') or request.args.get('return_group_id') or device.group_id,
    )
    return_group_id = _group_id_str(return_group)

    try:
        device.last_backup_status = None
        extra = dict(device.extra_parameters or {})
        extra.pop("last_backup_failure_category", None)
        extra.pop("last_backup_failure_label", None)
        extra.pop("last_backup_failure_message", None)
        extra.pop("last_backup_failure_at", None)
        device.extra_parameters = extra
        db.commit()
        flash('Erro de backup limpo com sucesso.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Falha ao limpar erro de backup: {e}', 'error')
    finally:
        db.close()

    return redirect(url_for(
        'tenant_devices.view_device',
        tenant_slug=tenant_slug,
        device_id=device_id,
        group_id=return_group_id,
    ))


@bp.route('/subgroup-connection', methods=['POST'])
@login_required
@tenant_admin_required
def bulk_subgroup_connection(tenant_slug):
    """
    Gerencia subgrupos reais dentro do grupo principal:
    - create: cria (ou reutiliza por nome) um subgrupo e move dispositivos
    - assign_existing: move dispositivos para um subgrupo existente
    - remove: remove dispositivos de qualquer subgrupo
    - delete_existing: exclui (desativa) um subgrupo existente e remove vínculos
    """
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )
    return_group = _resolve_group_context(
        db,
        tenant.id,
        request.form.get('group_id') or request.args.get('group_id') or request.args.get('return_group_id'),
    )
    return_group_id = _group_id_str(return_group)

    if not return_group:
        msg = "Para configurar subgrupo, abra primeiro um Grupo (Provedor) específico."
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "warning")
        return redirect(url_for('tenant_devices.list_devices', tenant_slug=tenant_slug))

    action = str(request.form.get('subgroup_action') or "create").strip().lower()
    connection_type = _normalize_connection_type(request.form.get('subgroup_connection_type'))
    subgroup_name = str(request.form.get("subgroup_name") or "").strip()
    subgroup_id_raw = str(request.form.get("subgroup_id") or "").strip()
    return_subgroup_raw = str(request.form.get("subgroup") or request.args.get("subgroup") or "").strip()
    raw_device_ids = request.form.getlist('device_ids')

    def _build_redirect(target_subgroup=None, *, clear_subgroup=False):
        subgroup_param = None if clear_subgroup else (return_subgroup_raw or None)
        if target_subgroup is not None:
            subgroup_param = str(target_subgroup.id)
        return redirect(
            url_for(
                'tenant_devices.list_devices',
                tenant_slug=tenant_slug,
                group_id=return_group_id,
                subgroup=subgroup_param,
            )
        )

    selected_ids = []
    seen = set()
    for raw in raw_device_ids:
        try:
            parsed = uuid.UUID(str(raw))
        except (TypeError, ValueError):
            continue
        key = str(parsed)
        if key in seen:
            continue
        seen.add(key)
        selected_ids.append(parsed)

    if action == "clear":
        action = "remove"
    elif action == "delete":
        action = "delete_existing"
    elif action == "set":
        action = "create"
        if not subgroup_name:
            subgroup_name = f"Subgrupo {connection_type.upper() if connection_type else 'Direto'}"

    if action not in {"update_existing", "delete_existing"} and not selected_ids:
        msg = "Selecione ao menos um dispositivo para mover no subgrupo."
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "warning")
        return _build_redirect()

    if action not in {"create", "assign_existing", "assign", "remove", "update_existing", "delete_existing"}:
        msg = "Acao de subgrupo invalida."
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "error")
        return _build_redirect()

    if action in {"create", "update_existing"} and connection_type not in VALID_SUBGROUP_CONNECTION_TYPES:
        msg = "Tipo de conexao do subgrupo invalido (direct, vpn ou jump_host)."
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "error")
        return _build_redirect()

    if action in {"create", "update_existing"} and not subgroup_name:
        msg = "Informe o nome do subgrupo."
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "error")
        return _build_redirect()

    target_subgroup = None
    selected_lookup = {str(x) for x in selected_ids}

    def _find_target_subgroup():
        if not subgroup_id_raw:
            return None
        try:
            subgroup_uuid = uuid.UUID(subgroup_id_raw)
        except (TypeError, ValueError):
            return None
        return (
            db.query(DeviceSubgroup)
            .filter(
                DeviceSubgroup.id == subgroup_uuid,
                DeviceSubgroup.tenant_id == tenant.id,
                DeviceSubgroup.group_id == return_group.id,
                DeviceSubgroup.is_active == True,
            )
            .first()
        )

    if action == "create":
        target_subgroup = DeviceSubgroupService.get_or_create_by_name(
            db,
            tenant_id=tenant.id,
            group_id=return_group.id,
            name=subgroup_name,
            connection_type=connection_type,
        )
    elif action in {"assign_existing", "assign", "update_existing", "delete_existing"}:
        target_subgroup = _find_target_subgroup()
        if not target_subgroup:
            msg = "Selecione um subgrupo existente."
            db.close()
            if is_ajax:
                return jsonify({"ok": False, "error": msg}), 400
            flash(msg, "error")
            return _build_redirect()
        if action == "update_existing":
            target_subgroup.name = subgroup_name
            target_subgroup.connection_type = connection_type

    if action == "update_existing":
        devices = db.query(Device).filter(
            Device.tenant_id == tenant.id,
            Device.group_id == return_group.id,
            Device.is_active.isnot(False),
        ).all()
    elif action == "delete_existing":
        devices = db.query(Device).filter(
            Device.tenant_id == tenant.id,
            Device.group_id == return_group.id,
            Device.subgroup_id == target_subgroup.id,
            Device.is_active.isnot(False),
        ).all()
    else:
        devices = db.query(Device).filter(
            Device.tenant_id == tenant.id,
            Device.group_id == return_group.id,
            Device.id.in_(selected_ids),
            Device.is_active.isnot(False),
        ).all()

    if not devices and action not in {"update_existing", "delete_existing"}:
        msg = "Nenhum dispositivo valido encontrado dentro do grupo atual."
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "warning")
        return _build_redirect(target_subgroup=target_subgroup)

    updated = 0
    for device in devices:
        previous_subgroup_id = str(device.subgroup_id) if getattr(device, "subgroup_id", None) else None
        if action == "remove":
            next_subgroup_id = None
        elif action == "delete_existing":
            if previous_subgroup_id == str(target_subgroup.id):
                next_subgroup_id = None
            else:
                next_subgroup_id = device.subgroup_id
        elif action == "update_existing":
            if str(device.id) in selected_lookup:
                next_subgroup_id = target_subgroup.id
            elif previous_subgroup_id == str(target_subgroup.id):
                next_subgroup_id = None
            else:
                next_subgroup_id = device.subgroup_id
        else:
            next_subgroup_id = target_subgroup.id

        if previous_subgroup_id == (str(next_subgroup_id) if next_subgroup_id else None):
            continue

        device.subgroup_id = next_subgroup_id

        # limpa chaves legadas para evitar conflito na resolucao do modo efetivo
        extra = dict(device.extra_parameters or {})
        extra.pop(SUBGROUP_CONNECTION_ENABLED_KEY, None)
        extra.pop(SUBGROUP_CONNECTION_TYPE_KEY, None)
        extra.pop(SUBGROUP_CONNECTION_UPDATED_AT_KEY, None)
        extra.pop("subgroup_connection_enabled", None)
        extra.pop("subgroup_connection_type", None)
        device.extra_parameters = extra
        updated += 1

    if action == "delete_existing" and target_subgroup:
        target_subgroup.is_active = False

    db.commit()

    from app.services.activity_service import ActivityService
    user_id = session.get('user_id')
    ActivityService.log_action(
        db,
        tenant.id,
        user_id,
        "UPDATE_CONNECTION_SUBGROUP",
        (
            f"Subgrupo de conexao atualizado: action={action} "
            f"subgroup={getattr(target_subgroup, 'name', 'none')} "
            f"type={getattr(target_subgroup, 'connection_type', connection_type or 'n/a')} "
            f"devices={updated}"
        ),
        request.remote_addr,
    )

    if action == "remove":
        human_msg = f"Subgrupo removido de {updated} dispositivo(s)."
    elif action == "delete_existing":
        human_msg = (
            f"Subgrupo '{target_subgroup.name}' excluído com sucesso. "
            f"{updated} dispositivo(s) desvinculado(s)."
        )
    elif action in {"assign_existing", "assign"}:
        human_msg = f"{updated} dispositivo(s) movido(s) para o subgrupo '{target_subgroup.name}'."
    elif action == "update_existing":
        human_mode = {
            "direct": "Direto",
            "vpn": "VPN",
            "jump_host": "Jump Host",
        }.get(target_subgroup.connection_type, target_subgroup.connection_type)
        human_msg = (
            f"Subgrupo '{target_subgroup.name}' atualizado para modo {human_mode}. "
            f"{updated} alteração(ões) de associação aplicadas."
        )
    else:
        human_mode = {
            "direct": "Direto",
            "vpn": "VPN",
            "jump_host": "Jump Host",
        }.get(target_subgroup.connection_type, target_subgroup.connection_type)
        human_msg = (
            f"Subgrupo '{target_subgroup.name}' salvo com modo {human_mode}. "
            f"{updated} dispositivo(s) associado(s)."
        )

    db.close()
    if is_ajax:
        return jsonify(
            {
                "ok": True,
                "updated": updated,
                "action": action,
                "connection_type": getattr(target_subgroup, "connection_type", ""),
                "subgroup_name": getattr(target_subgroup, "name", ""),
                "message": human_msg,
            }
        ), 200

    flash(human_msg, "success")
    if action == "delete_existing":
        return _build_redirect(clear_subgroup=True)
    return _build_redirect(target_subgroup=target_subgroup)


@bp.route('/<device_id>/run', methods=['POST'])
@login_required
def run_backup(tenant_slug, device_id):
    """Executa backup de um dispositivo específico."""
    from app.tasks.backups import run_backup_task, run_vpn_group_backups_task
    from app.services.realtime_backup_logs import register_task, append_task_log
    
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    force_stop_cleared = _clear_global_force_stop_flag()
    
    try:
        device_uuid = uuid.UUID(device_id)
    except ValueError:
        flash('ID de dispositivo inválido', 'error')
        return redirect(url_for('tenant_devices.list_devices', tenant_slug=tenant_slug))
    
    # Busca nome para log
    device = db.query(Device).filter(
        Device.id == device_uuid,
        Device.tenant_id == tenant.id,
    ).first()
    
    if not device:
        flash('Dispositivo não encontrado', 'error')
        db.close()
        return redirect(url_for('tenant_devices.list_devices', tenant_slug=tenant_slug))

    if device.group and not bool(getattr(device.group, "is_active", True)):
        flash(
            f'Grupo "{device.group.name}" está inativo. Reative o grupo antes de executar backups.',
            'warning',
        )
        db.close()
        return redirect(url_for('tenant_devices.list_devices', tenant_slug=tenant_slug, group_id=str(device.group_id)))

    return_group = _resolve_group_context(
        db,
        tenant.id,
        request.form.get('group_id') or request.args.get('group_id') or request.args.get('return_group_id') or device.group_id,
    )
    return_group_id = _group_id_str(return_group)

    device_name = device.name

    if force_stop_cleared:
        flash('Bloqueio global de parada foi removido automaticamente para iniciar novo backup.', 'warning')

    # Enfileira backup (direto ou VPN)
    if device.group and uses_vpn_tunnel(device.group, device=device):
        task = run_vpn_group_backups_task.apply_async(
            args=[str(device.group_id), str(tenant.id), [str(device.id)]],
            kwargs={"force_vpn": bool(_device_subgroup_connection_type(device) == "vpn" and not uses_vpn_tunnel(device.group))},
            queue='vpn_queue'
        )
        queue_mode = 'vpn_queue'
    else:
        queue_mode = _backup_queue_for_device(device)
        task = run_backup_task.apply_async(args=[str(device_uuid)], queue=queue_mode)

    register_task(
        task_id=str(task.id),
        tenant_id=str(tenant.id),
        device_id=str(device.id),
        device_name=device_name,
        group_id=str(device.group_id) if device.group_id else None,
    )
    append_task_log(
        str(task.id),
        device_name,
        f"Task criada na fila {queue_mode}. Aguardando worker iniciar.",
        "info",
    )

    # LOG ACTIVITY: Manual Backup (queued)
    from app.services.activity_service import ActivityService
    user_id = session.get('user_id')
    details = (
        f"Manual backup queued for {device_name}. "
        f"task_id={task.id} queue={queue_mode}"
    )
    ActivityService.log_action(db, tenant.id, user_id, "BACKUP_MANUAL", details, request.remote_addr)
    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )
    if is_ajax:
        db.close()
        return jsonify({
            'ok': True,
            'task_id': str(task.id),
            'queue': queue_mode,
            'device_name': device_name,
            'is_bulk': False,
            'status_url': url_for('tenant_backups.task_status', tenant_slug=tenant_slug, task_id=str(task.id)),
            'logs_url': url_for('tenant_backups.task_logs', tenant_slug=tenant_slug, task_id=str(task.id)),
            'cancel_url': url_for('tenant_backups.cancel_task', tenant_slug=tenant_slug, task_id=str(task.id)),
        }), 202

    flash(f'Backup enfileirado com sucesso! Task: {task.id}', 'success')
    
    db.close()
    return redirect(url_for(
        'tenant_devices.list_devices',
        tenant_slug=tenant_slug,
        group_id=return_group_id,
    ))


@bp.route('/<device_id>/test-connection', methods=['POST'])
@login_required
def test_connection(tenant_slug, device_id):
    """Valida conexao/autenticacao do dispositivo sem executar backup."""
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    try:
        device_uuid = uuid.UUID(device_id)
    except ValueError:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            db.close()
            return jsonify({'ok': False, 'error': 'ID de dispositivo invalido.'}), 400
        flash('ID de dispositivo invalido', 'error')
        db.close()
        return redirect(url_for('tenant_devices.list_devices', tenant_slug=tenant_slug))

    device = db.query(Device).filter(
        Device.id == device_uuid,
        Device.tenant_id == tenant.id,
    ).first()
    if not device:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            db.close()
            return jsonify({'ok': False, 'error': 'Dispositivo nao encontrado.'}), 404
        flash('Dispositivo nao encontrado', 'error')
        db.close()
        return redirect(url_for('tenant_devices.list_devices', tenant_slug=tenant_slug))

    return_group = _resolve_group_context(
        db,
        tenant.id,
        request.form.get('group_id') or request.args.get('group_id') or request.args.get('return_group_id') or device.group_id,
    )
    return_group_id = _group_id_str(return_group)

    device_name = device.name
    device_ip = device.ip_address
    device_port = device.port

    payload = None
    try:
        target_queue = 'vpn_queue' if (device.group and uses_vpn_tunnel(device.group, device=device)) else 'celery'
        test_task = run_connection_test_task.apply_async(
            args=[str(device.id)],
            queue=target_queue,
        )
        payload = test_task.get(timeout=60)
    except CeleryTimeoutError:
        payload = {
            'ok': False,
            'message': 'Timeout no teste de conexao (worker).',
            'protocol': 'ssh' if not device.use_telnet else 'telnet',
            'elapsed_ms': 60000,
        }
    except Exception as exc:
        payload = {
            'ok': False,
            'message': f'Erro ao executar teste de conexao: {exc}',
            'protocol': 'ssh' if not device.use_telnet else 'telnet',
            'elapsed_ms': 0,
        }

    test_success = bool(payload.get('ok'))
    test_message = payload.get('message') or payload.get('error') or 'Falha de conexao.'
    test_protocol = payload.get('protocol') or ('ssh' if not device.use_telnet else 'telnet')
    test_elapsed = int(payload.get('elapsed_ms') or 0)

    from app.services.activity_service import ActivityService
    user_id = session.get('user_id')
    status_text = "SUCCESS" if test_success else "FAILED"
    details = (
        f"Connection test {status_text} for {device_name} "
        f"({device_ip}:{device_port}) protocol={test_protocol} "
        f"elapsed_ms={test_elapsed} msg={test_message}"
    )
    ActivityService.log_action(db, tenant.id, user_id, "TEST_CONNECTION", details, request.remote_addr)

    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )
    if is_ajax:
        db.close()
        return jsonify({
            'ok': test_success,
            'device_name': device_name,
            'message': test_message,
            'protocol': test_protocol,
            'elapsed_ms': test_elapsed,
        }), (200 if test_success else 422)

    if test_success:
        flash(f"Conexao com {device_name} validada com sucesso ({test_protocol.upper()}).", 'success')
    else:
        flash(f"Falha no teste de conexao de {device_name}: {test_message}", 'error')
    db.close()
    return redirect(url_for(
        'tenant_devices.view_device',
        tenant_slug=tenant_slug,
        device_id=device_id,
        group_id=return_group_id,
    ))

@bp.route('/run-all', methods=['POST'])
@login_required
def run_backup_all(tenant_slug):
    """Executa backup em massa no contexto atual (grupo/subgrupo/filtro)."""
    from celery import chord
    from app.tasks.backups import (
        run_backup_task,
        run_vpn_group_backups_task,
        enqueue_jump_and_vpn_after_direct_phase_task,
    )
    from app.services.realtime_backup_logs import register_task, update_task_meta, append_task_log
    
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    force_stop_cleared = _clear_global_force_stop_flag()
    from app.tasks.backups import reset_circuit_breakers_for_new_batch
    reset_circuit_breakers_for_new_batch()
    include_unvalidated = _value_bool(request.form.get("include_unvalidated"), default=False)

    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )
    bulk_task_id = f"bulk-{uuid.uuid4()}" if is_ajax else None

    # Pega o grupo se especificado
    group_id = request.form.get('group_id')
    include_unscheduled = _value_bool(
        request.form.get("include_unscheduled"),
        # Backup em massa global deve incluir todos os dispositivos ativos por padrão.
        # Em contexto de grupo/subgrupo, mantemos o mesmo comportamento (também incluir todos).
        default=True,
    )
    subgroup_raw = (request.form.get('subgroup') or request.args.get('subgroup') or '').strip()
    subgroup_filter_uuid = None
    subgroup_filter_none = False
    if subgroup_raw:
        if subgroup_raw.lower() in {"none", "__none__"}:
            subgroup_filter_none = True
            subgroup_raw = "none"
        else:
            try:
                subgroup_filter_uuid = uuid.UUID(subgroup_raw)
            except (TypeError, ValueError):
                subgroup_raw = ""
    
    # Busca dispositivos ativos no escopo atual.
    # Por padrao em contexto de grupo/subgrupo, "Backup Todos" deve incluir os nao agendados.
    query = db.query(Device).outerjoin(
        DeviceGroup,
        Device.group_id == DeviceGroup.id,
    ).filter(
        Device.tenant_id == tenant.id,
        Device.is_active.isnot(False),
        or_(Device.group_id.is_(None), DeviceGroup.is_active.is_(True)),
    )
    if not include_unscheduled:
        query = query.filter(Device.backup_scheduled == True)
    
    if group_id:
        try:
            group_uuid = uuid.UUID(group_id)
            query = query.filter(Device.group_id == group_uuid)
        except ValueError:
            pass

    if subgroup_filter_none:
        query = query.filter(Device.subgroup_id.is_(None))
    elif subgroup_filter_uuid:
        query = query.filter(Device.subgroup_id == subgroup_filter_uuid)
    
    base_devices = query.all()
    skipped_not_ready = 0
    skipped_jump_unreachable = 0
    preflight_summary = {
        "enabled": False,
        "skipped_not_ready": 0,
        "audit_queued": 0,
        "counts": {},
    }
    jump_preflight_summary = {
        "enabled": False,
        "checked_endpoints": 0,
        "total_endpoints": 0,
        "probe_truncated": False,
        "skipped_jump_unreachable": 0,
        "unreachable_endpoints": [],
    }
    excluded_type_ids = resolve_mass_backup_excluded_type_ids(db)
    devices, excluded_mass_devices = _split_mass_backup_devices(base_devices, excluded_type_ids)
    skipped_mass_excluded = len(excluded_mass_devices)
    devices, preflight_summary = _bulk_preflight_filter_devices(
        devices,
        tenant_id=str(tenant.id),
        bulk_task_id=bulk_task_id,
        include_unvalidated=include_unvalidated,
        enqueue_audit=False,
    )
    skipped_not_ready = int(preflight_summary.get("skipped_not_ready") or 0)
    devices, jump_preflight_summary = _bulk_preflight_jump_hosts(
        devices,
        tenant_id=str(tenant.id),
    )
    skipped_jump_unreachable = int(jump_preflight_summary.get("skipped_jump_unreachable") or 0)
    if not devices:
        scope_label = "ativos" if include_unscheduled else "agendados"
        msg = (
            f"Nenhum dispositivo {scope_label} elegivel para backup em massa "
            f"({MASS_BACKUP_EXCLUDED_TYPE_LABEL} sao ignorados nesse fluxo)."
        )
        if skipped_not_ready:
            msg += f" {skipped_not_ready} dispositivo(s) foram ignorados no preflight de conectividade."
        if skipped_jump_unreachable:
            msg += (
                f" {skipped_jump_unreachable} dispositivo(s) foram ignorados por indisponibilidade de Jump Host "
                f"({_format_jump_unreachable_summary(jump_preflight_summary)})."
            )
        if is_ajax:
            db.close()
            return jsonify({'ok': False, 'error': msg}), 400
        flash(msg, 'warning')
        db.close()
        return redirect(url_for(
            'tenant_devices.list_devices',
            tenant_slug=tenant_slug,
            group_id=group_id,
            subgroup=subgroup_raw or None,
        ))

    if is_ajax and bulk_task_id:
        reserved_response = _reserve_bulk_or_json_error(tenant.id, bulk_task_id)
        if reserved_response:
            db.close()
            return reserved_response
    
    queued_direct = 0
    queued_jump = 0
    queued_subgroup = 0
    queued_vpn_groups = 0
    queued_vpn_devices = 0
    queued_jump_groups = 0
    direct_by_group = {}
    jump_by_group = {}
    vpn_by_group = {}
    direct_no_group_devices = []
    direct_payload = []
    jump_payload = []
    vpn_payload = []
    phased_deferred = False
    single_group_mode = bool(group_id)
    group_summary = {}
    direct_signatures = []
    throttle_counters = {}
    child_task_ids = []
    child_task_device_count = {}

    if is_ajax:
        register_task(
            task_id=bulk_task_id,
            tenant_id=str(tenant.id),
            device_name="Backup em massa",
            group_id=str(group_id) if group_id else None,
        )
        if force_stop_cleared:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                "Bloqueio global anterior removido automaticamente para iniciar novo lote.",
                "warning",
            )
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                f"Iniciando enfileiramento para {len(devices)} dispositivos agendados (elegiveis).",
                "info",
            )
        if skipped_mass_excluded:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                (
                    f"{skipped_mass_excluded} dispositivo(s) de tipo {MASS_BACKUP_EXCLUDED_TYPE_LABEL} "
                    "foram ignorados no backup em massa."
                ),
                "warning",
            )
        append_task_log(
            bulk_task_id,
            "Backup em massa",
            (
                "Escopo da execucao: "
                + ("todos os dispositivos ativos do contexto atual." if include_unscheduled else "somente dispositivos com agendamento ativo.")
            ),
            "info",
        )
        if skipped_not_ready:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                (
                    f"Preflight: {skipped_not_ready} dispositivo(s) ignorados por conectividade "
                    f"(audit_queued={int(preflight_summary.get('audit_queued') or 0)})."
                ),
                "warning",
            )
        elif include_unvalidated:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                "Preflight em modo informativo (include_unvalidated=1): nenhum dispositivo foi excluido por conectividade.",
                "info",
            )
        if skipped_jump_unreachable:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                (
                    f"Preflight Jump Host: {skipped_jump_unreachable} dispositivo(s) ignorados por indisponibilidade "
                    f"de bastion ({_format_jump_unreachable_summary(jump_preflight_summary)})."
                ),
                "warning",
            )

    for device in devices:
        group_name = device.group.name if device.group else "Sem grupo"
        effective_mode = (
            get_effective_connection_type(device.group, device=device)
            if device.group
            else "direct"
        )
        if _device_subgroup_connection_type(device):
            queued_subgroup += 1
        if group_name not in group_summary:
            group_summary[group_name] = {
                "group_name": group_name,
                "connection_mode": effective_mode or "direct",
                "devices": 0,
            }
        group_summary[group_name]["devices"] += 1

        subgroup_mode = _device_subgroup_connection_type(device)
        force_vpn_subgroup = bool(subgroup_mode == "vpn" and device.group and not uses_vpn_tunnel(device.group))

        if device.group and uses_vpn_tunnel(device.group, device=device):
            _append_group_phase_bucket(vpn_by_group, device, force_vpn=force_vpn_subgroup)
            continue

        if device.group and uses_jump_host(device.group, device=device):
            _append_group_phase_bucket(jump_by_group, device)
            continue

        if single_group_mode:
            # No contexto de grupo, apenas conexoes diretas ficam por dispositivo.
            # VPN/Jump Host ficam agrupados para evitar reconectar o mesmo tunel varias vezes.
            direct_no_group_devices.append(device)
            continue

        if device.group:
            _append_group_phase_bucket(direct_by_group, device)
        else:
            direct_no_group_devices.append(device)

    direct_payload = _finalize_group_phase_payload(direct_by_group)
    jump_payload = _finalize_group_phase_payload(jump_by_group)
    vpn_payload = _finalize_group_phase_payload(vpn_by_group)

    queued_direct = sum(len(item["device_ids"]) for item in direct_payload) + len(direct_no_group_devices)
    queued_jump = sum(len(item["device_ids"]) for item in jump_payload)
    queued_jump_groups = len(jump_payload)
    queued_vpn_groups = len(vpn_payload)

    if single_group_mode:
        queued_direct = len(direct_no_group_devices)
        queued_vpn_devices = sum(len(item["device_ids"]) for item in vpn_payload)
        if is_ajax:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                (
                    "Modo de grupo/subgrupo detectado: conexoes diretas por dispositivo; "
                    f"Jump Host agrupado em {queued_jump_groups} grupo(s) e VPN agrupada em "
                    f"{queued_vpn_groups} grupo(s)."
                ),
                "info",
            )

    # Fase 1 (direto): por grupo no bulk global; por dispositivo no modo de grupo/subgrupo.
    if not single_group_mode:
        for item in direct_payload:
            args = [item["group_id"], str(tenant.id), item["device_ids"]]
            if bulk_task_id:
                args.append(bulk_task_id)
            if is_ajax:
                direct_task_id = str(uuid.uuid4())
                task_sig = run_vpn_group_backups_task.s(*args).set(
                    task_id=direct_task_id,
                    queue='celery',
                )
                child_task_ids.append(direct_task_id)
                child_task_device_count[direct_task_id] = len(item["device_ids"])
                register_task(
                    task_id=direct_task_id,
                    tenant_id=str(tenant.id),
                    device_name=f"Grupo Direto {item.get('group_name') or item['group_id']}",
                    group_id=item["group_id"],
                )
                update_task_meta(
                    direct_task_id,
                    device_ids=list(item["device_ids"]),
                    device_total=len(item["device_ids"]),
                )
            else:
                task_sig = run_vpn_group_backups_task.s(*args).set(queue='celery')
            direct_signatures.append(task_sig)

    for device in direct_no_group_devices:
        # Sem grupo: mantém task unitária.
        countdown = _next_countdown_for_device(device, throttle_counters) if is_ajax else 0
        target_queue = _backup_queue_for_device(device)
        if is_ajax:
            direct_task_id = str(uuid.uuid4())
            task_sig = run_backup_task.s(str(device.id), bulk_task_id).set(
                task_id=direct_task_id,
                countdown=countdown,
                queue=target_queue,
            )
            child_task_ids.append(direct_task_id)
            child_task_device_count[direct_task_id] = 1
            register_task(
                task_id=direct_task_id,
                tenant_id=str(tenant.id),
                device_id=str(device.id),
                device_name=device.name,
                group_id=None,
            )
        else:
            task_sig = run_backup_task.s(str(device.id), bulk_task_id).set(queue=target_queue)
        direct_signatures.append(task_sig)

    # Fase 1: direto (por grupo no bulk global, por dispositivo no modo de grupo)
    # Fase 2: jump host (por dispositivo no bulk global, com lock por Jump Host)
    # Fase 3: vpn (por grupo no bulk global)
    if single_group_mode and direct_signatures and (jump_payload or vpn_payload):
        callback_sig = enqueue_jump_and_vpn_after_direct_phase_task.s(
            str(tenant.id),
            jump_payload,
            vpn_payload,
            bulk_task_id,
        ).set(queue='celery')
        chord(direct_signatures)(callback_sig)
        phased_deferred = True
        if is_ajax:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                (
                    f"Fase 1 (direto) enfileirada: {queued_direct} dispositivos. "
                    f"Fase 2 (jump host): {queued_jump} dispositivo(s) em {queued_jump_groups} grupo(s). "
                    f"Fase 3 (VPN): {queued_vpn_groups} grupo(s) apos fase 2."
                ),
                "info",
            )
    elif single_group_mode and direct_signatures:
        for sig in direct_signatures:
            sig.apply_async()
    elif single_group_mode and (jump_payload or vpn_payload):
        enqueue_jump_and_vpn_after_direct_phase_task.apply_async(
            args=[None, str(tenant.id), jump_payload, vpn_payload, bulk_task_id],
            queue='celery',
        )
        phased_deferred = True
        if is_ajax:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                (
                    f"Sem fase direta. Iniciando fase 2 (jump host: {queued_jump} dispositivo(s) em {queued_jump_groups} grupo(s)) "
                    f"e fase 3 (VPN: {queued_vpn_groups} grupo(s)) em sequencia."
                ),
                "info",
            )
    elif direct_signatures:
        if jump_payload or vpn_payload:
            callback_sig = enqueue_jump_and_vpn_after_direct_phase_task.s(
                str(tenant.id),
                jump_payload,
                vpn_payload,
                bulk_task_id,
            ).set(queue='celery')
            chord(direct_signatures)(callback_sig)
            phased_deferred = True
            if is_ajax:
                append_task_log(
                    bulk_task_id,
                    "Backup em massa",
                    (
                        f"Fase 1 (direto) enfileirada: {queued_direct} dispositivos. "
                        f"Fase 2 (jump host): {queued_jump} dispositivo(s) em {queued_jump_groups} grupo(s). "
                        f"Fase 3 (VPN): {queued_vpn_groups} grupo(s) apos fase 2."
                    ),
                    "info",
                )
        else:
            for sig in direct_signatures:
                sig.apply_async()
    elif jump_payload or vpn_payload:
        # Sem dispositivos diretos: inicia da fase 2.
        enqueue_jump_and_vpn_after_direct_phase_task.apply_async(
            args=[None, str(tenant.id), jump_payload, vpn_payload, bulk_task_id],
            queue='celery',
        )
        phased_deferred = True
        if is_ajax:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                (
                    f"Sem fase direta. Iniciando fase 2 (jump host: {queued_jump} dispositivo(s) em {queued_jump_groups} grupo(s)) "
                    f"e fase 3 (VPN: {queued_vpn_groups} grupo(s)) em sequencia."
                ),
                "info",
            )
    
    # LOG ACTIVITY
    from app.services.activity_service import ActivityService
    user_id = session.get('user_id')
    details = (
        f"Bulk backup queued: direto={queued_direct} jump={queued_jump} "
        f"jump_groups={queued_jump_groups} vpn_groups={queued_vpn_groups} "
        f"({len(devices)} total). "
        f"subgrupo_conexao={queued_subgroup} "
        f"phased_deferred={'yes' if phased_deferred else 'no'} "
        f"preflight_skipped={skipped_not_ready} "
        f"preflight_jump_unreachable={skipped_jump_unreachable} "
        f"preflight_audit_queued={int(preflight_summary.get('audit_queued') or 0)}"
    )
    ActivityService.log_action(db, tenant.id, user_id, "BACKUP_BULK", details, request.remote_addr)
    
    if is_ajax:
        summary_rows = sorted(group_summary.values(), key=lambda row: (-row["devices"], row["group_name"].lower()))
        total_tasks = len(child_task_ids) + (queued_jump + queued_vpn_groups if phased_deferred else 0)
        child_task_ids, child_task_device_count, total_tasks = _merge_existing_bulk_children(
            bulk_task_id,
            child_task_ids,
            child_task_device_count,
            total_tasks,
        )
        skipped_jump_device_ids = list(jump_preflight_summary.get("skipped_device_ids") or [])
        visible_total_devices = len(devices) + len(skipped_jump_device_ids)
        initial_failure_counts = {"connection": len(skipped_jump_device_ids)} if skipped_jump_device_ids else {}
        update_task_meta(
            bulk_task_id,
            is_bulk=True,
            operation_kind="backup_bulk",
            status='running',
            progress=5,
            completed=False,
            cancel_requested=False,
            message=(
                f"{total_tasks} tarefas planejadas para processamento."
                if phased_deferred
                else f"{len(child_task_ids)} tarefas enfileiradas para processamento."
            ),
            total_devices=visible_total_devices,
            queued_direct=queued_direct,
            queued_jump=queued_jump,
            queued_jump_groups=queued_jump_groups,
            queued_vpn_groups=queued_vpn_groups,
            queued_vpn_devices=queued_vpn_devices,
            queued_subgroup=queued_subgroup,
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
            group_summary=summary_rows,
            skipped_not_ready=skipped_not_ready,
            skipped_jump_unreachable=skipped_jump_unreachable,
            skipped_jump_device_ids=skipped_jump_device_ids,
            skipped_mass_excluded=skipped_mass_excluded,
            failure_category_counts=initial_failure_counts,
            preflight_enabled=bool(preflight_summary.get("enabled")),
            preflight_include_unvalidated=bool(preflight_summary.get("include_unvalidated")),
            preflight_audit_queued=int(preflight_summary.get("audit_queued") or 0),
            preflight_counts=dict(preflight_summary.get("counts") or {}),
            jump_preflight_enabled=bool(jump_preflight_summary.get("enabled")),
            jump_preflight_checked_endpoints=int(jump_preflight_summary.get("checked_endpoints") or 0),
            jump_preflight_total_endpoints=int(jump_preflight_summary.get("total_endpoints") or 0),
            jump_preflight_probe_truncated=bool(jump_preflight_summary.get("probe_truncated")),
            jump_preflight_unreachable_endpoints=list(jump_preflight_summary.get("unreachable_endpoints") or []),
        )
        if phased_deferred:
            append_task_log(
                bulk_task_id,
                "Backup em massa",
                (
                    f"Enfileirado fase 1: {queued_direct} diretos. "
                    f"Fase 2: {queued_jump} dispositivo(s) via jump host em {queued_jump_groups} grupo(s). "
                    f"Fase 3: {queued_vpn_groups} grupo(s) VPN aguardando callback."
                ),
                "success",
            )
        else:
            if single_group_mode:
                append_task_log(
                    bulk_task_id,
                    "Backup em massa",
                    (
                        f"Enfileirado: {queued_direct} task(s) por dispositivo "
                        f"(fila celery={max(0, queued_direct - queued_vpn_devices)}, "
                        f"vpn_queue={queued_vpn_devices})."
                    ),
                    "success",
                )
            else:
                append_task_log(
                    bulk_task_id,
                    "Backup em massa",
                    (
                        f"Enfileirado: {queued_direct} diretos + {queued_vpn_groups} grupos VPN "
                        f"({len(child_task_ids)} tasks Celery)."
                    ),
                    "success",
                )
        db.close()
        return jsonify({
            'ok': True,
            'is_bulk': True,
            'task_id': bulk_task_id,
            'device_name': "Backup em massa",
            'queued_direct': queued_direct,
            'queued_jump': queued_jump,
            'queued_jump_groups': queued_jump_groups,
            'queued_vpn_groups': queued_vpn_groups,
            'queued_vpn_devices': queued_vpn_devices,
            'queued_subgroup': queued_subgroup,
            'total_devices': visible_total_devices,
            'total_tasks': total_tasks,
            'operation_kind': 'backup_bulk',
            'group_summary': summary_rows,
            'skipped_not_ready': skipped_not_ready,
            'skipped_jump_unreachable': skipped_jump_unreachable,
            'skipped_jump_device_ids': skipped_jump_device_ids,
            'skipped_mass_excluded': skipped_mass_excluded,
            'preflight_enabled': bool(preflight_summary.get("enabled")),
            'preflight_include_unvalidated': bool(preflight_summary.get("include_unvalidated")),
            'preflight_audit_queued': int(preflight_summary.get("audit_queued") or 0),
            'preflight_counts': dict(preflight_summary.get("counts") or {}),
            'jump_preflight_enabled': bool(jump_preflight_summary.get("enabled")),
            'jump_preflight_checked_endpoints': int(jump_preflight_summary.get("checked_endpoints") or 0),
            'jump_preflight_total_endpoints': int(jump_preflight_summary.get("total_endpoints") or 0),
            'jump_preflight_probe_truncated': bool(jump_preflight_summary.get("probe_truncated")),
            'jump_preflight_unreachable_endpoints': list(jump_preflight_summary.get("unreachable_endpoints") or []),
            'status_url': url_for('tenant_backups.bulk_task_status', tenant_slug=tenant_slug, task_id=bulk_task_id),
            'logs_url': url_for('tenant_backups.bulk_task_logs', tenant_slug=tenant_slug, task_id=bulk_task_id),
            'cancel_url': url_for('tenant_backups.cancel_bulk_task', tenant_slug=tenant_slug, task_id=bulk_task_id),
        }), 202

    db.close()
    if force_stop_cleared:
        flash('Bloqueio global de parada foi removido automaticamente para iniciar este lote.', 'warning')
    if phased_deferred:
        flash(
            f'Fase 1 enfileirada: {queued_direct} diretos. '
            f'Fase 2 (jump host): {queued_jump} dispositivo(s) em {queued_jump_groups} grupo(s). '
            f'Fase 3 (VPN): {queued_vpn_groups} grupo(s) iniciara apos finalizar a fase 2.',
            'success'
        )
    else:
        if single_group_mode:
            flash(
                (
                    f'Backups enfileirados: {queued_direct} task(s) por dispositivo '
                    f'(celery={max(0, queued_direct - queued_vpn_devices)}, '
                    f'vpn_queue={queued_vpn_devices}).'
                ),
                'success'
            )
        else:
            flash(
                f'Backups enfileirados: {queued_direct} diretos + {queued_jump} jump + {queued_vpn_groups} grupo(s) VPN.',
                'success'
            )
    if skipped_mass_excluded:
        flash(
            f'{skipped_mass_excluded} dispositivo(s) {MASS_BACKUP_EXCLUDED_TYPE_LABEL} foram ignorados no backup em massa.',
            'warning'
        )
    if skipped_not_ready:
        flash(
            (
                f'{skipped_not_ready} dispositivo(s) foram ignorados no preflight de conectividade '
                f"(audit_queued={int(preflight_summary.get('audit_queued') or 0)})."
            ),
            'warning'
        )
    if skipped_jump_unreachable:
        flash(
            (
                f'{skipped_jump_unreachable} dispositivo(s) foram ignorados por indisponibilidade de Jump Host '
                f"({_format_jump_unreachable_summary(jump_preflight_summary)})."
            ),
            'warning'
        )
    return redirect(url_for(
        'tenant_devices.list_devices',
        tenant_slug=tenant_slug,
        group_id=group_id,
        subgroup=subgroup_raw or None,
    ))


@bp.route('/run-connection-audit-all', methods=['POST'])
@login_required
def run_connection_audit_all(tenant_slug):
    """Executa teste em massa de ping + login (sem backup)."""
    from app.services.realtime_backup_logs import register_task, update_task_meta, append_task_log

    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )

    group_id = request.form.get('group_id')
    query = db.query(Device).outerjoin(
        DeviceGroup,
        Device.group_id == DeviceGroup.id,
    ).filter(
        Device.tenant_id == tenant.id,
        Device.is_active == True,
        or_(Device.group_id.is_(None), DeviceGroup.is_active.is_(True)),
    )
    if group_id:
        try:
            group_uuid = uuid.UUID(group_id)
            query = query.filter(Device.group_id == group_uuid)
        except ValueError:
            pass

    devices = query.all()
    if not devices:
        if is_ajax:
            db.close()
            return jsonify({'ok': False, 'error': 'Nenhum dispositivo ativo encontrado para validacao manual.'}), 400
        flash('Nenhum dispositivo ativo encontrado para validacao manual.', 'warning')
        db.close()
        return redirect(url_for('tenant_schedules.list_schedules', tenant_slug=tenant_slug))

    queued = 0
    queued_direct = 0
    queued_vpn = 0
    child_task_ids = []
    child_task_device_count = {}
    bulk_task_id = f"bulk-{uuid.uuid4()}"

    register_task(
        task_id=bulk_task_id,
        tenant_id=str(tenant.id),
        device_name="Validacao manual de conectividade",
        group_id=str(group_id) if group_id else None,
    )
    append_task_log(
        bulk_task_id,
        "Validacao manual",
        f"Iniciando enfileiramento para {len(devices)} dispositivo(s) ativo(s).",
        "info",
    )

    for device in devices:
        child_id = str(uuid.uuid4())
        target_queue = 'vpn_queue' if (device.group and uses_vpn_tunnel(device.group, device=device)) else 'celery'
        run_device_connection_audit_task.apply_async(
            args=[str(device.id), bulk_task_id],
            task_id=child_id,
            queue=target_queue,
        )
        queued += 1
        if target_queue == 'vpn_queue':
            queued_vpn += 1
        else:
            queued_direct += 1
        child_task_ids.append(child_id)
        child_task_device_count[child_id] = 1
        register_task(
            task_id=child_id,
            tenant_id=str(tenant.id),
            device_id=str(device.id),
            device_name=device.name,
            group_id=str(device.group_id) if device.group_id else None,
        )

    update_task_meta(
        bulk_task_id,
        is_bulk=True,
        operation_kind="connection_audit",
        status='running',
        progress=5,
        completed=False,
        cancel_requested=False,
        message=f"{queued} testes planejados para processamento.",
        total_devices=len(devices),
        queued_direct=queued_direct,
        queued_vpn_groups=queued_vpn,
        total_tasks=queued,
        done_tasks=0,
        success_tasks=0,
        failed_tasks=0,
        running_tasks=0,
        queued_tasks=queued,
        done_devices=0,
        success_devices=0,
        failed_devices=0,
        no_ping_devices=0,
        ping_ok_login_fail_devices=0,
        ping_login_ok_devices=0,
        child_task_ids=child_task_ids,
        child_task_device_count=child_task_device_count,
        finished_task_ids=[],
        group_summary=[],
    )
    append_task_log(
        bulk_task_id,
        "Validacao manual",
        f"Enfileirado: {queued} tarefa(s) de validacao de acesso.",
        "success",
    )

    payload = {
        'ok': True,
        'is_bulk': True,
        'task_id': bulk_task_id,
        'device_name': "Validacao manual de conectividade",
        'queued_direct': queued_direct,
        'queued_vpn_groups': queued_vpn,
        'total_devices': len(devices),
        'total_tasks': queued,
        'operation_kind': 'connection_audit',
        'status_url': url_for('tenant_backups.bulk_task_status', tenant_slug=tenant_slug, task_id=bulk_task_id),
        'logs_url': url_for('tenant_backups.bulk_task_logs', tenant_slug=tenant_slug, task_id=bulk_task_id),
        'cancel_url': url_for('tenant_backups.cancel_bulk_task', tenant_slug=tenant_slug, task_id=bulk_task_id),
    }

    db.close()
    if is_ajax:
        return jsonify(payload), 202

    flash(f'Validacao manual de conectividade enfileirada para {queued} dispositivo(s).', 'success')
    return redirect(url_for('tenant_schedules.list_schedules', tenant_slug=tenant_slug))


@bp.route('/run-selected', methods=['POST'])
@login_required
def run_backup_selected(tenant_slug):
    """Executa backup dos dispositivos selecionados."""
    from celery import chord
    from app.tasks.backups import (
        run_backup_task,
        run_vpn_group_backups_task,
        enqueue_jump_and_vpn_after_direct_phase_task,
    )
    from app.services.realtime_backup_logs import register_task, update_task_meta, append_task_log
    
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    force_stop_cleared = _clear_global_force_stop_flag()
    from app.tasks.backups import reset_circuit_breakers_for_new_batch
    reset_circuit_breakers_for_new_batch()
    include_unvalidated = _value_bool(request.form.get("include_unvalidated"), default=False)
    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )
    return_group = _resolve_group_context(
        db,
        tenant.id,
        request.form.get('group_id') or request.args.get('group_id') or request.args.get('return_group_id'),
    )
    return_group_id = _group_id_str(return_group)
    return_subgroup = (request.form.get('subgroup') or request.args.get('subgroup') or '').strip()
    if return_subgroup:
        if return_subgroup.lower() in {"none", "__none__"}:
            return_subgroup = "none"
        else:
            try:
                return_subgroup = str(uuid.UUID(return_subgroup))
            except (TypeError, ValueError):
                return_subgroup = ""
    
    # Pega IDs selecionados
    device_ids = request.form.getlist('device_ids')
    
    if not device_ids:
        if is_ajax:
            db.close()
            return jsonify({'ok': False, 'error': 'Nenhum dispositivo selecionado.'}), 400
        flash('Nenhum dispositivo selecionado', 'warning')
        db.close()
        return redirect(url_for(
            'tenant_devices.list_devices',
            tenant_slug=tenant_slug,
            group_id=return_group_id,
            subgroup=return_subgroup or None,
        ))
    
    queued_direct = 0
    queued_jump = 0
    queued_subgroup = 0
    invalid_count = 0
    skipped_not_ready = 0
    skipped_jump_unreachable = 0
    skipped_mass_excluded = 0
    preflight_summary = {
        "enabled": False,
        "skipped_not_ready": 0,
        "audit_queued": 0,
        "counts": {},
    }
    jump_preflight_summary = {
        "enabled": False,
        "checked_endpoints": 0,
        "total_endpoints": 0,
        "probe_truncated": False,
        "skipped_jump_unreachable": 0,
        "unreachable_endpoints": [],
    }
    direct_by_group = {}
    jump_by_group = {}
    vpn_by_group = {}
    throttle_counters = {}
    selected_devices = []
    direct_signatures = []
    child_task_ids = []
    child_task_device_count = {}
    direct_no_group_devices = []
    direct_payload = []
    jump_payload = []
    vpn_payload = []
    bulk_task_id = f"selected-{uuid.uuid4()}" if is_ajax else None
    queued_jump_groups = 0
    queued_vpn_groups = 0
    phased_deferred = False
    excluded_type_ids = resolve_mass_backup_excluded_type_ids(db)
    seen_devices = set()
    candidate_devices = []

    for device_id in device_ids:
        try:
            device_uuid = uuid.UUID(device_id)
            device = db.query(Device).outerjoin(
                DeviceGroup,
                Device.group_id == DeviceGroup.id,
            ).filter(
                Device.id == device_uuid,
                Device.tenant_id == tenant.id,
                or_(Device.group_id.is_(None), DeviceGroup.is_active.is_(True)),
            ).first()
            if not device:
                continue
            device_key = str(device.id)
            if device_key in seen_devices:
                continue
            seen_devices.add(device_key)
            candidate_devices.append(device)
        except ValueError:
            invalid_count += 1

    selected_devices, excluded_mass_devices = _split_mass_backup_devices(candidate_devices, excluded_type_ids)
    skipped_mass_excluded = len(excluded_mass_devices)
    selected_devices, preflight_summary = _bulk_preflight_filter_devices(
        selected_devices,
        tenant_id=str(tenant.id),
        bulk_task_id=bulk_task_id,
        include_unvalidated=include_unvalidated,
        enqueue_audit=False,
    )
    skipped_not_ready = int(preflight_summary.get("skipped_not_ready") or 0)
    selected_devices, jump_preflight_summary = _bulk_preflight_jump_hosts(
        selected_devices,
        tenant_id=str(tenant.id),
    )
    skipped_jump_unreachable = int(jump_preflight_summary.get("skipped_jump_unreachable") or 0)
    if not selected_devices:
        msg = "Nenhum dispositivo selecionado elegivel para backup em massa."
        if skipped_mass_excluded:
            msg += f" Ignorados por tipo ({MASS_BACKUP_EXCLUDED_TYPE_LABEL}): {skipped_mass_excluded}."
        if skipped_not_ready:
            msg += f" Ignorados no preflight de conectividade: {skipped_not_ready}."
        if skipped_jump_unreachable:
            msg += (
                " Ignorados por indisponibilidade de Jump Host: "
                f"{skipped_jump_unreachable} ({_format_jump_unreachable_summary(jump_preflight_summary)})."
            )
        if is_ajax:
            db.close()
            return jsonify({'ok': False, 'error': msg}), 400
        flash(msg, 'warning')
        db.close()
        return redirect(url_for(
            'tenant_devices.list_devices',
            tenant_slug=tenant_slug,
            group_id=return_group_id,
            subgroup=return_subgroup or None,
        ))

    if is_ajax and bulk_task_id:
        reserved_response = _reserve_bulk_or_json_error(tenant.id, bulk_task_id)
        if reserved_response:
            db.close()
            return reserved_response

    for device in selected_devices:
        if _device_subgroup_connection_type(device):
            queued_subgroup += 1
        subgroup_mode = _device_subgroup_connection_type(device)
        force_vpn_subgroup = bool(subgroup_mode == "vpn" and device.group and not uses_vpn_tunnel(device.group))

        if device.group and uses_vpn_tunnel(device.group, device=device):
            _append_group_phase_bucket(vpn_by_group, device, force_vpn=force_vpn_subgroup)
            continue
        if device.group and uses_jump_host(device.group, device=device):
            _append_group_phase_bucket(jump_by_group, device)
            continue
        if device.group:
            _append_group_phase_bucket(direct_by_group, device)
        else:
            direct_no_group_devices.append(device)

    direct_payload = _finalize_group_phase_payload(direct_by_group)
    jump_payload = _finalize_group_phase_payload(jump_by_group)
    vpn_payload = _finalize_group_phase_payload(vpn_by_group)

    queued_direct = sum(len(item["device_ids"]) for item in direct_payload) + len(direct_no_group_devices)
    queued_jump = sum(len(item["device_ids"]) for item in jump_payload)
    queued_jump_groups = len(jump_payload)
    queued_vpn_groups = len(vpn_payload)

    for item in direct_payload:
        args = [item["group_id"], str(tenant.id), item["device_ids"]]
        if bulk_task_id:
            args.append(bulk_task_id)
        if is_ajax:
            direct_task_id = str(uuid.uuid4())
            task_sig = run_vpn_group_backups_task.s(*args).set(
                task_id=direct_task_id,
                queue='celery',
            )
            child_task_ids.append(direct_task_id)
            child_task_device_count[direct_task_id] = len(item["device_ids"])
            register_task(
                task_id=direct_task_id,
                tenant_id=str(tenant.id),
                device_name=f"Grupo Direto {item.get('group_name') or item['group_id']}",
                group_id=item["group_id"],
            )
            update_task_meta(
                direct_task_id,
                device_ids=list(item["device_ids"]),
                device_total=len(item["device_ids"]),
            )
        else:
            task_sig = run_vpn_group_backups_task.s(*args).set(queue='celery')
        direct_signatures.append(task_sig)

    for device in direct_no_group_devices:
        target_queue = _backup_queue_for_device(device)
        if is_ajax:
            countdown = _next_countdown_for_device(device, throttle_counters)
            direct_task_id = str(uuid.uuid4())
            task_sig = run_backup_task.s(str(device.id), bulk_task_id).set(
                task_id=direct_task_id,
                countdown=countdown,
                queue=target_queue,
            )
            child_task_ids.append(direct_task_id)
            child_task_device_count[direct_task_id] = 1
            register_task(
                task_id=direct_task_id,
                tenant_id=str(tenant.id),
                device_id=str(device.id),
                device_name=device.name,
                group_id=None,
            )
        else:
            task_sig = run_backup_task.s(str(device.id), bulk_task_id).set(queue=target_queue)
        direct_signatures.append(task_sig)

    if is_ajax:
        register_task(
            task_id=bulk_task_id,
            tenant_id=str(tenant.id),
            device_name="Backup selecionados",
            group_id=return_group_id,
        )
        if force_stop_cleared:
            append_task_log(
                bulk_task_id,
                "Backup selecionados",
                "Bloqueio global anterior removido automaticamente para iniciar novo lote.",
                "warning",
            )
        if skipped_mass_excluded:
            append_task_log(
                bulk_task_id,
                "Backup selecionados",
                (
                    f"{skipped_mass_excluded} dispositivo(s) de tipo {MASS_BACKUP_EXCLUDED_TYPE_LABEL} "
                    "foram ignorados no backup em massa."
                ),
                "warning",
            )
        if skipped_not_ready:
            append_task_log(
                bulk_task_id,
                "Backup selecionados",
                (
                    f"Preflight: {skipped_not_ready} dispositivo(s) ignorados por conectividade "
                    f"(audit_queued={int(preflight_summary.get('audit_queued') or 0)})."
                ),
                "warning",
            )
        elif include_unvalidated:
            append_task_log(
                bulk_task_id,
                "Backup selecionados",
                "Preflight em modo informativo (include_unvalidated=1): nenhum dispositivo foi excluido por conectividade.",
                "info",
            )
        if skipped_jump_unreachable:
            append_task_log(
                bulk_task_id,
                "Backup selecionados",
                (
                    f"Preflight Jump Host: {skipped_jump_unreachable} dispositivo(s) ignorados por indisponibilidade "
                    f"de bastion ({_format_jump_unreachable_summary(jump_preflight_summary)})."
                ),
                "warning",
            )

    if direct_signatures:
        if jump_payload or vpn_payload:
            callback_sig = enqueue_jump_and_vpn_after_direct_phase_task.s(
                str(tenant.id),
                jump_payload,
                vpn_payload,
                bulk_task_id,
            ).set(queue='celery')
            chord(direct_signatures)(callback_sig)
            phased_deferred = True
            if is_ajax:
                append_task_log(
                    bulk_task_id,
                    "Backup selecionados",
                    (
                        f"Fase 1 (direto) enfileirada: {queued_direct} dispositivos. "
                        f"Fase 2 (jump host): {queued_jump} dispositivo(s) em {queued_jump_groups} grupo(s). "
                        f"Fase 3 (VPN): {queued_vpn_groups} grupo(s) apos fase 2."
                    ),
                    "info",
                )
        else:
            for sig in direct_signatures:
                sig.apply_async()
    elif jump_payload or vpn_payload:
        enqueue_jump_and_vpn_after_direct_phase_task.apply_async(
            args=[None, str(tenant.id), jump_payload, vpn_payload, bulk_task_id],
            queue='celery',
        )
        phased_deferred = True
        if is_ajax:
            append_task_log(
                bulk_task_id,
                "Backup selecionados",
                (
                    f"Sem fase direta. Iniciando fase 2 (jump host: {queued_jump} dispositivo(s) em {queued_jump_groups} grupo(s)) "
                    f"e fase 3 (VPN: {queued_vpn_groups} grupo(s)) em sequencia."
                ),
                "info",
            )
    
    # LOG ACTIVITY
    from app.services.activity_service import ActivityService
    user_id = session.get('user_id')
    details = (
        f"Selected backup queued: direto={queued_direct} jump={queued_jump} "
        f"jump_groups={queued_jump_groups} vpn_groups={queued_vpn_groups}, "
        f"subgrupo_conexao={queued_subgroup}, invalidos={invalid_count}, "
        f"pulados_not_ready={skipped_not_ready}, "
        f"pulados_jump_unreachable={skipped_jump_unreachable}, "
        f"preflight_audit_queued={int(preflight_summary.get('audit_queued') or 0)}."
    )
    ActivityService.log_action(db, tenant.id, user_id, "BACKUP_SELECTED", details, request.remote_addr)

    total_queued = queued_direct + queued_jump + queued_vpn_groups

    if is_ajax:
        total_tasks = len(child_task_ids) + (queued_jump + queued_vpn_groups if phased_deferred else 0)
        child_task_ids, child_task_device_count, total_tasks = _merge_existing_bulk_children(
            bulk_task_id,
            child_task_ids,
            child_task_device_count,
            total_tasks,
        )
        skipped_jump_device_ids = list(jump_preflight_summary.get("skipped_device_ids") or [])
        visible_total_devices = len(selected_devices) + len(skipped_jump_device_ids)
        initial_failure_counts = {"connection": len(skipped_jump_device_ids)} if skipped_jump_device_ids else {}
        update_task_meta(
            bulk_task_id,
            is_bulk=True,
            operation_kind="backup_bulk",
            status='running',
            progress=5,
            completed=False,
            cancel_requested=False,
            message=(
                f"{total_tasks} tarefas planejadas para processamento."
                if phased_deferred
                else f"{len(child_task_ids)} tarefas enfileiradas para processamento."
            ),
            total_devices=visible_total_devices,
            queued_direct=queued_direct,
            queued_jump=queued_jump,
            queued_jump_groups=queued_jump_groups,
            queued_vpn_groups=queued_vpn_groups,
            queued_subgroup=queued_subgroup,
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
            skipped_not_ready=skipped_not_ready,
            skipped_jump_unreachable=skipped_jump_unreachable,
            skipped_jump_device_ids=skipped_jump_device_ids,
            skipped_mass_excluded=skipped_mass_excluded,
            failure_category_counts=initial_failure_counts,
            preflight_enabled=bool(preflight_summary.get("enabled")),
            preflight_include_unvalidated=bool(preflight_summary.get("include_unvalidated")),
            preflight_audit_queued=int(preflight_summary.get("audit_queued") or 0),
            preflight_counts=dict(preflight_summary.get("counts") or {}),
            jump_preflight_enabled=bool(jump_preflight_summary.get("enabled")),
            jump_preflight_checked_endpoints=int(jump_preflight_summary.get("checked_endpoints") or 0),
            jump_preflight_total_endpoints=int(jump_preflight_summary.get("total_endpoints") or 0),
            jump_preflight_probe_truncated=bool(jump_preflight_summary.get("probe_truncated")),
            jump_preflight_unreachable_endpoints=list(jump_preflight_summary.get("unreachable_endpoints") or []),
        )
        append_task_log(
            bulk_task_id,
            "Backup selecionados",
            (
                f"Enfileirado: {queued_direct} diretos + {queued_jump} jump + {queued_vpn_groups} grupos VPN "
                f"({len(selected_devices)} dispositivos selecionados)."
            ),
            "success",
        )
        db.close()
        return jsonify({
            'ok': True,
            'is_bulk': True,
            'task_id': bulk_task_id,
            'device_name': "Backup selecionados",
            'queued_direct': queued_direct,
            'queued_jump': queued_jump,
            'queued_jump_groups': queued_jump_groups,
            'queued_vpn_groups': queued_vpn_groups,
            'queued_subgroup': queued_subgroup,
            'total_devices': visible_total_devices,
            'total_tasks': total_tasks,
            'operation_kind': 'backup_bulk',
            'skipped_not_ready': skipped_not_ready,
            'skipped_jump_unreachable': skipped_jump_unreachable,
            'skipped_jump_device_ids': skipped_jump_device_ids,
            'skipped_mass_excluded': skipped_mass_excluded,
            'preflight_enabled': bool(preflight_summary.get("enabled")),
            'preflight_include_unvalidated': bool(preflight_summary.get("include_unvalidated")),
            'preflight_audit_queued': int(preflight_summary.get("audit_queued") or 0),
            'preflight_counts': dict(preflight_summary.get("counts") or {}),
            'jump_preflight_enabled': bool(jump_preflight_summary.get("enabled")),
            'jump_preflight_checked_endpoints': int(jump_preflight_summary.get("checked_endpoints") or 0),
            'jump_preflight_total_endpoints': int(jump_preflight_summary.get("total_endpoints") or 0),
            'jump_preflight_probe_truncated': bool(jump_preflight_summary.get("probe_truncated")),
            'jump_preflight_unreachable_endpoints': list(jump_preflight_summary.get("unreachable_endpoints") or []),
            'status_url': url_for('tenant_backups.bulk_task_status', tenant_slug=tenant_slug, task_id=bulk_task_id),
            'logs_url': url_for('tenant_backups.bulk_task_logs', tenant_slug=tenant_slug, task_id=bulk_task_id),
            'cancel_url': url_for('tenant_backups.cancel_bulk_task', tenant_slug=tenant_slug, task_id=bulk_task_id),
        }), 202

    db.close()

    if force_stop_cleared:
        flash('Bloqueio global de parada foi removido automaticamente para iniciar os backups selecionados.', 'warning')
    if total_queued <= 0:
        if skipped_mass_excluded or skipped_not_ready:
            flash('Nenhum dispositivo selecionado elegivel para backup em massa.', 'warning')
        else:
            flash('Nenhum dispositivo selecionado para backup.', 'warning')
    else:
        flash(
            f'Backups selecionados enfileirados: {queued_direct} diretos + {queued_jump} jump + {queued_vpn_groups} grupo(s) VPN.',
            'success'
        )
    if skipped_mass_excluded:
        flash(
            f'{skipped_mass_excluded} dispositivo(s) {MASS_BACKUP_EXCLUDED_TYPE_LABEL} foram ignorados no backup em massa.',
            'warning'
        )
    if skipped_not_ready:
        flash(
            (
                f'{skipped_not_ready} dispositivo(s) foram ignorados no preflight de conectividade '
                f"(audit_queued={int(preflight_summary.get('audit_queued') or 0)})."
            ),
            'warning'
        )
    if skipped_jump_unreachable:
        flash(
            (
                f'{skipped_jump_unreachable} dispositivo(s) foram ignorados por indisponibilidade de Jump Host '
                f"({_format_jump_unreachable_summary(jump_preflight_summary)})."
            ),
            'warning'
        )
    
    return redirect(url_for(
        'tenant_devices.list_devices',
        tenant_slug=tenant_slug,
        group_id=return_group_id,
        subgroup=return_subgroup or None,
    ))


@bp.route('/run-reprocess-failures', methods=['POST'])
@login_required
def run_reprocess_failures(tenant_slug):
    """Reprocessa dispositivos com falhas recentes (hoje ou ultimas 24h)."""
    from celery import chord
    from app.tasks.backups import (
        run_backup_task,
        run_vpn_group_backups_task,
        enqueue_jump_and_vpn_after_direct_phase_task,
    )
    from app.services.realtime_backup_logs import register_task, update_task_meta, append_task_log
    from app.services.backup_diagnostics import classify_failure, is_transient_failure

    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    from app.tasks.backups import reset_circuit_breakers_for_new_batch
    reset_circuit_breakers_for_new_batch()
    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )
    scope = (request.form.get('scope') or 'today').strip().lower()
    transient_only = (request.form.get('transient_only') or '').strip().lower() in {"1", "true", "on", "yes"}
    now = datetime.utcnow()
    use_current_failed_state = scope in {"last_failed", "current_failed", "failed_now"}
    if use_current_failed_state:
        since = None
        scope_label = "ultimo backup em falha"
    elif scope == '24h':
        since = now - timedelta(hours=24)
        scope_label = "ultimas 24h"
    else:
        since = datetime(now.year, now.month, now.day, 0, 0, 0)
        scope_label = "hoje"

    latest_failed_by_device = {}
    if use_current_failed_state:
        failed_device_rows = (
            db.query(Device)
            .outerjoin(DeviceGroup, Device.group_id == DeviceGroup.id)
            .filter(
                Device.tenant_id == tenant.id,
                Device.is_active == True,
                Device.backup_scheduled == True,
                or_(Device.group_id.is_(None), DeviceGroup.is_active.is_(True)),
                Device.last_backup_status == "failure",
            )
            .order_by(Device.name.asc())
            .all()
        )
        for device in failed_device_rows:
            extra = dict(getattr(device, "extra_parameters", None) or {})
            category = str(extra.get("last_backup_failure_category") or "").strip().lower()
            if not category:
                category = classify_failure(extra.get("last_backup_failure_message") or "")
            if transient_only and not is_transient_failure(category):
                continue
            latest_failed_by_device[str(device.id)] = {
                "device_id": str(device.id),
                "category": category,
                "backup_id": None,
                "started_at": getattr(device, "last_backup_at", None).isoformat() if getattr(device, "last_backup_at", None) else None,
            }
    else:
        failed_rows = (
            db.query(Backup)
            .join(Device, Device.id == Backup.device_id)
            .outerjoin(DeviceGroup, Device.group_id == DeviceGroup.id)
            .filter(
                Device.tenant_id == tenant.id,
                Device.is_active == True,
                Device.backup_scheduled == True,
                or_(Device.group_id.is_(None), DeviceGroup.is_active.is_(True)),
                Backup.status == BackupStatus.FAILED,
                Backup.started_at.isnot(None),
                Backup.started_at >= since,
            )
            .order_by(Backup.started_at.desc())
            .all()
        )

        for row in failed_rows:
            key = str(row.device_id)
            if key in latest_failed_by_device:
                continue
            category = classify_failure(row.error_message or "")
            if transient_only and not is_transient_failure(category):
                continue
            latest_failed_by_device[key] = {
                "device_id": key,
                "category": category,
                "backup_id": str(row.id),
                "started_at": row.started_at.isoformat() if row.started_at else None,
            }

    if not latest_failed_by_device:
        msg = (
            f"Nenhuma falha {'transitoria ' if transient_only else ''}encontrada para {scope_label}."
        )
        if is_ajax:
            db.close()
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "warning")
        db.close()
        return redirect(url_for('tenant_schedules.list_schedules', tenant_slug=tenant_slug))

    target_device_ids = [uuid.UUID(v["device_id"]) for v in latest_failed_by_device.values()]
    devices = (
        db.query(Device)
        .outerjoin(DeviceGroup, Device.group_id == DeviceGroup.id)
        .filter(
            Device.tenant_id == tenant.id,
            Device.id.in_(target_device_ids),
            Device.is_active == True,
            Device.backup_scheduled == True,
            or_(Device.group_id.is_(None), DeviceGroup.is_active.is_(True)),
        )
        .all()
    )

    skipped_not_ready = 0
    skipped_jump_unreachable = 0
    preflight_summary = {
        "enabled": False,
        "skipped_not_ready": 0,
        "audit_queued": 0,
        "counts": {},
    }
    jump_preflight_summary = {
        "enabled": False,
        "checked_endpoints": 0,
        "total_endpoints": 0,
        "probe_truncated": False,
        "skipped_jump_unreachable": 0,
        "unreachable_endpoints": [],
    }
    excluded_type_ids = resolve_mass_backup_excluded_type_ids(db)
    devices, excluded_mass_devices = _split_mass_backup_devices(devices, excluded_type_ids)
    skipped_mass_excluded = len(excluded_mass_devices)
    bulk_task_id = f"bulk-{uuid.uuid4()}"
    devices, preflight_summary = _bulk_preflight_filter_devices(
        devices,
        tenant_id=str(tenant.id),
        bulk_task_id=bulk_task_id,
        enqueue_audit=False,
    )
    skipped_not_ready = int(preflight_summary.get("skipped_not_ready") or 0)
    devices, jump_preflight_summary = _bulk_preflight_jump_hosts(
        devices,
        tenant_id=str(tenant.id),
    )
    skipped_jump_unreachable = int(jump_preflight_summary.get("skipped_jump_unreachable") or 0)

    if not devices:
        msg = (
            "Nenhum dispositivo elegivel para reprocessar "
            f"({MASS_BACKUP_EXCLUDED_TYPE_LABEL} sao ignorados nesse fluxo em massa)."
        )
        if skipped_not_ready:
            msg += f" {skipped_not_ready} dispositivo(s) foram ignorados no preflight de conectividade."
        if skipped_jump_unreachable:
            msg += (
                f" {skipped_jump_unreachable} dispositivo(s) foram ignorados por indisponibilidade de Jump Host "
                f"({_format_jump_unreachable_summary(jump_preflight_summary)})."
            )
        if is_ajax:
            db.close()
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "warning")
        db.close()
        return redirect(url_for('tenant_schedules.list_schedules', tenant_slug=tenant_slug))

    if is_ajax and bulk_task_id:
        reserved_response = _reserve_bulk_or_json_error(tenant.id, bulk_task_id)
        if reserved_response:
            db.close()
            return reserved_response

    queued_direct = 0
    queued_jump = 0
    queued_jump_groups = 0
    queued_vpn_groups = 0
    direct_by_group = {}
    jump_by_group = {}
    vpn_by_group = {}
    direct_no_group_devices = []
    direct_payload = []
    jump_payload = []
    vpn_payload = []
    direct_signatures = []
    throttle_counters = {}
    phased_deferred = False
    child_task_ids = []
    child_task_device_count = {}
    register_task(
        task_id=bulk_task_id,
        tenant_id=str(tenant.id),
        device_name="Reprocessamento de falhas",
        group_id=None,
    )
    append_task_log(
        bulk_task_id,
        "Reprocessamento",
        (
            f"Iniciando reprocessamento ({scope_label}) para {len(devices)} dispositivo(s) "
            f"{'com falhas transitorias' if transient_only else 'com falha'}."
        ),
        "info",
    )
    if skipped_mass_excluded:
        append_task_log(
            bulk_task_id,
            "Reprocessamento",
            (
                f"{skipped_mass_excluded} dispositivo(s) de tipo {MASS_BACKUP_EXCLUDED_TYPE_LABEL} "
                "foram ignorados no fluxo em massa."
            ),
            "warning",
        )
    if skipped_not_ready:
        append_task_log(
            bulk_task_id,
            "Reprocessamento",
            (
                f"Preflight: {skipped_not_ready} dispositivo(s) ignorados por conectividade "
                f"(audit_queued={int(preflight_summary.get('audit_queued') or 0)})."
            ),
            "warning",
        )
    if skipped_jump_unreachable:
        append_task_log(
            bulk_task_id,
            "Reprocessamento",
            (
                f"Preflight Jump Host: {skipped_jump_unreachable} dispositivo(s) ignorados por indisponibilidade "
                f"de bastion ({_format_jump_unreachable_summary(jump_preflight_summary)})."
            ),
            "warning",
        )
    for device in devices:
        subgroup_mode = _device_subgroup_connection_type(device)
        force_vpn_subgroup = bool(subgroup_mode == "vpn" and device.group and not uses_vpn_tunnel(device.group))

        if device.group and uses_vpn_tunnel(device.group, device=device):
            _append_group_phase_bucket(vpn_by_group, device, force_vpn=force_vpn_subgroup)
            continue
        if device.group and uses_jump_host(device.group, device=device):
            _append_group_phase_bucket(jump_by_group, device)
            continue
        if device.group:
            _append_group_phase_bucket(direct_by_group, device)
        else:
            direct_no_group_devices.append(device)

    direct_payload = _finalize_group_phase_payload(direct_by_group)
    jump_payload = _finalize_group_phase_payload(jump_by_group)
    vpn_payload = _finalize_group_phase_payload(vpn_by_group)

    queued_direct = sum(len(item["device_ids"]) for item in direct_payload) + len(direct_no_group_devices)
    queued_jump = sum(len(item["device_ids"]) for item in jump_payload)
    queued_jump_groups = len(jump_payload)
    queued_vpn_groups = len(vpn_payload)

    for item in direct_payload:
        direct_task_id = str(uuid.uuid4())
        sig = run_vpn_group_backups_task.s(
            item["group_id"],
            str(tenant.id),
            item["device_ids"],
            bulk_task_id,
        ).set(task_id=direct_task_id, queue='celery')
        child_task_ids.append(direct_task_id)
        child_task_device_count[direct_task_id] = len(item["device_ids"])
        register_task(
            task_id=direct_task_id,
            tenant_id=str(tenant.id),
            device_name=f"Grupo Direto {item.get('group_name') or item['group_id']}",
            group_id=item["group_id"],
        )
        update_task_meta(
            direct_task_id,
            device_ids=list(item["device_ids"]),
            device_total=len(item["device_ids"]),
        )
        direct_signatures.append(sig)

    for device in direct_no_group_devices:
        countdown = _next_countdown_for_device(device, throttle_counters)
        target_queue = _backup_queue_for_device(device)
        direct_task_id = str(uuid.uuid4())
        sig = run_backup_task.s(str(device.id), bulk_task_id).set(
            task_id=direct_task_id,
            countdown=countdown,
            queue=target_queue,
        )
        child_task_ids.append(direct_task_id)
        child_task_device_count[direct_task_id] = 1
        register_task(
            task_id=direct_task_id,
            tenant_id=str(tenant.id),
            device_id=str(device.id),
            device_name=device.name,
            group_id=str(device.group_id) if device.group_id else None,
        )
        direct_signatures.append(sig)

    if direct_signatures:
        if jump_payload or vpn_payload:
            callback_sig = enqueue_jump_and_vpn_after_direct_phase_task.s(
                str(tenant.id),
                jump_payload,
                vpn_payload,
                bulk_task_id,
            ).set(queue='celery')
            chord(direct_signatures)(callback_sig)
            phased_deferred = True
        else:
            for sig in direct_signatures:
                sig.apply_async()
    elif jump_payload or vpn_payload:
        enqueue_jump_and_vpn_after_direct_phase_task.apply_async(
            args=[None, str(tenant.id), jump_payload, vpn_payload, bulk_task_id],
            queue='celery',
        )
        phased_deferred = True

    total_tasks = len(child_task_ids) + (queued_jump + queued_vpn_groups if phased_deferred else 0)
    child_task_ids, child_task_device_count, total_tasks = _merge_existing_bulk_children(
        bulk_task_id,
        child_task_ids,
        child_task_device_count,
        total_tasks,
    )
    skipped_jump_device_ids = list(jump_preflight_summary.get("skipped_device_ids") or [])
    visible_total_devices = len(devices) + len(skipped_jump_device_ids)
    initial_failure_counts = {"connection": len(skipped_jump_device_ids)} if skipped_jump_device_ids else {}
    update_task_meta(
        bulk_task_id,
        is_bulk=True,
        operation_kind="backup_reprocess",
        status='running',
        progress=5,
        completed=False,
        cancel_requested=False,
        message=(
            f"{total_tasks} tarefas planejadas para reprocessamento."
            if phased_deferred
            else f"{total_tasks} tarefas enfileiradas para reprocessamento."
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
        skipped_not_ready=skipped_not_ready,
        skipped_jump_unreachable=skipped_jump_unreachable,
        skipped_jump_device_ids=skipped_jump_device_ids,
        skipped_mass_excluded=skipped_mass_excluded,
        failure_category_counts=initial_failure_counts,
        preflight_enabled=bool(preflight_summary.get("enabled")),
        preflight_audit_queued=int(preflight_summary.get("audit_queued") or 0),
        preflight_counts=dict(preflight_summary.get("counts") or {}),
        jump_preflight_enabled=bool(jump_preflight_summary.get("enabled")),
        jump_preflight_checked_endpoints=int(jump_preflight_summary.get("checked_endpoints") or 0),
        jump_preflight_total_endpoints=int(jump_preflight_summary.get("total_endpoints") or 0),
        jump_preflight_probe_truncated=bool(jump_preflight_summary.get("probe_truncated")),
        jump_preflight_unreachable_endpoints=list(jump_preflight_summary.get("unreachable_endpoints") or []),
    )

    append_task_log(
        bulk_task_id,
        "Reprocessamento",
        (
            f"Enfileirado: {queued_direct} diretos + {queued_jump} jump + "
            f"{queued_vpn_groups} grupos VPN ({total_tasks} tasks Celery)."
        ),
        "success",
    )

    from app.services.activity_service import ActivityService
    user_id = session.get('user_id')
    ActivityService.log_action(
        db,
        tenant.id,
        user_id,
        "BACKUP_REPROCESS",
        (
            f"Reprocess queued ({scope_label}): transient_only={transient_only} "
            f"queued_direct={queued_direct} queued_jump={queued_jump} "
            f"queued_jump_groups={queued_jump_groups} queued_vpn_groups={queued_vpn_groups} "
            f"preflight_skipped={skipped_not_ready} "
            f"preflight_jump_unreachable={skipped_jump_unreachable} "
            f"preflight_audit_queued={int(preflight_summary.get('audit_queued') or 0)}"
        ),
        request.remote_addr,
    )

    response_payload = {
        "ok": True,
        "is_bulk": True,
        "task_id": bulk_task_id,
        "device_name": "Reprocessamento de falhas",
        "queued_direct": queued_direct,
        "queued_jump": queued_jump,
        "queued_jump_groups": queued_jump_groups,
        "queued_vpn_groups": queued_vpn_groups,
        "total_devices": visible_total_devices,
        "total_tasks": total_tasks,
        "operation_kind": "backup_reprocess",
        "skipped_not_ready": skipped_not_ready,
        "skipped_jump_unreachable": skipped_jump_unreachable,
        "skipped_jump_device_ids": skipped_jump_device_ids,
        "skipped_mass_excluded": skipped_mass_excluded,
        "preflight_enabled": bool(preflight_summary.get("enabled")),
        "preflight_audit_queued": int(preflight_summary.get("audit_queued") or 0),
        "preflight_counts": dict(preflight_summary.get("counts") or {}),
        "jump_preflight_enabled": bool(jump_preflight_summary.get("enabled")),
        "jump_preflight_checked_endpoints": int(jump_preflight_summary.get("checked_endpoints") or 0),
        "jump_preflight_total_endpoints": int(jump_preflight_summary.get("total_endpoints") or 0),
        "jump_preflight_probe_truncated": bool(jump_preflight_summary.get("probe_truncated")),
        "jump_preflight_unreachable_endpoints": list(jump_preflight_summary.get("unreachable_endpoints") or []),
        "status_url": url_for('tenant_backups.bulk_task_status', tenant_slug=tenant_slug, task_id=bulk_task_id),
        "logs_url": url_for('tenant_backups.bulk_task_logs', tenant_slug=tenant_slug, task_id=bulk_task_id),
        "cancel_url": url_for('tenant_backups.cancel_bulk_task', tenant_slug=tenant_slug, task_id=bulk_task_id),
    }
    db.close()

    if is_ajax:
        return jsonify(response_payload), 202

    flash(
        (
            f"Reprocessamento enfileirado: {queued_direct} diretos + "
            f"{queued_jump} jump + {queued_vpn_groups} grupo(s) VPN."
        ),
        "success",
    )
    if skipped_mass_excluded:
        flash(
            f'{skipped_mass_excluded} dispositivo(s) {MASS_BACKUP_EXCLUDED_TYPE_LABEL} foram ignorados no fluxo em massa.',
            'warning'
        )
    if skipped_not_ready:
        flash(
            (
                f'{skipped_not_ready} dispositivo(s) foram ignorados no preflight de conectividade '
                f"(audit_queued={int(preflight_summary.get('audit_queued') or 0)})."
            ),
            'warning'
        )
    if skipped_jump_unreachable:
        flash(
            (
                f'{skipped_jump_unreachable} dispositivo(s) foram ignorados por indisponibilidade de Jump Host '
                f"({_format_jump_unreachable_summary(jump_preflight_summary)})."
            ),
            'warning'
        )
    return redirect(url_for('tenant_schedules.list_schedules', tenant_slug=tenant_slug))

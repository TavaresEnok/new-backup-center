"""
Tasks Celery para monitoramento de dispositivos.

Essas tasks executam em background para não bloquear o servidor web.
"""

from datetime import datetime
import time
from app.celery_app import celery_app
from app.core.database import SessionLocal
from app.services.connection_mode import uses_jump_host, uses_vpn_tunnel
from app.services.monitor_service import MonitorService
from app.services.jump_host_service import jump_host_service, recommendation_for_category
import logging

logger = logging.getLogger(__name__)


def _is_global_stop_enabled() -> bool:
    try:
        from app.services.realtime_backup_logs import get_redis_client
        r = get_redis_client()
        if not r:
            return False
        return str(r.get("backup_center:force_stop_backups") or "").strip() == "1"
    except Exception:
        logger.exception("Falha ao verificar bloqueio global durante teste de conexao")
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
    return _is_global_stop_enabled() or _is_bulk_cancelled(bulk_task_id)


def _load_device_for_connection_audit(device_id: str, retries: int = 3):
    from sqlalchemy.orm import joinedload
    from app.models.device import Device

    last_exc = None
    for attempt in range(1, retries + 1):
        db = SessionLocal()
        try:
            device = (
                db.query(Device)
                .options(
                    joinedload(Device.group),
                    joinedload(Device.type),
                    joinedload(Device.subgroup),
                )
                .filter(Device.id == device_id)
                .first()
            )
            if device:
                db.expunge(device)
            return device
        except Exception as exc:
            last_exc = exc
            try:
                db.rollback()
            except Exception:
                pass
            logger.warning(
                "Falha ao carregar dispositivo %s para auditoria (tentativa %s/%s): %s",
                device_id,
                attempt,
                retries,
                exc,
            )
            if attempt < retries:
                time.sleep(0.25 * attempt)
        finally:
            db.close()
    if last_exc:
        raise last_exc
    return None


def _persist_connection_audit_state(
    device_id: str,
    extra_parameters: dict,
    last_connection_status: str | None = None,
    retries: int = 3,
) -> bool:
    from app.models.device import Device

    last_exc = None
    for attempt in range(1, retries + 1):
        db = SessionLocal()
        try:
            device = db.query(Device).filter(Device.id == device_id).first()
            if not device:
                return False
            if last_connection_status is not None:
                device.last_connection_status = last_connection_status
            device.extra_parameters = extra_parameters
            db.commit()
            return True
        except Exception as exc:
            last_exc = exc
            try:
                db.rollback()
            except Exception:
                pass
            logger.warning(
                "Falha ao persistir auditoria do dispositivo %s (tentativa %s/%s): %s",
                device_id,
                attempt,
                retries,
                exc,
            )
            if attempt < retries:
                time.sleep(0.25 * attempt)
        finally:
            db.close()
    if last_exc:
        raise last_exc
    return False


@celery_app.task(bind=True, queue='vpn_queue')
def run_connection_test_task(self, device_id: str):
    """Executa teste de conexao/autenticacao em worker com suporte a VPN (nmcli)."""
    from app.models.device import Device
    from app.services.connection_test_service import connection_test_service

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return {
                'ok': False,
                'error': f'Dispositivo {device_id} nao encontrado.',
                'protocol': 'unknown',
                'elapsed_ms': 0,
            }

        result = connection_test_service.test_device_connection(
            device=device,
            group=device.group,
            manage_vpn=True,
        )

        return {
            'ok': bool(result.success),
            'message': result.message,
            'protocol': result.protocol,
            'elapsed_ms': int(result.elapsed_ms),
            'device_id': device_id,
        }
    except Exception as exc:
        logger.exception('Erro ao testar conexao do dispositivo %s', device_id)
        return {
            'ok': False,
            'error': str(exc),
            'protocol': 'unknown',
            'elapsed_ms': 0,
            'device_id': device_id,
        }
    finally:
        db.close()


@celery_app.task(bind=True, queue='vpn_queue')
def run_group_vpn_test_task(self, group_id: str):
    """Valida a VPN de um grupo sem executar backup de dispositivos."""
    from app.models.device_group import DeviceGroup
    from app.services.vpn_service import vpn_service, VpnError
    from app.services.realtime_backup_logs import append_task_log, update_task_meta

    task_id = str(self.request.id)
    db = SessionLocal()
    try:
        group = db.query(DeviceGroup).filter(DeviceGroup.id == group_id).first()
        if not group:
            result = {
                "ok": False,
                "group_id": str(group_id),
                "message": f"Grupo {group_id} nao encontrado.",
            }
            update_task_meta(
                task_id,
                status="failed",
                progress=100,
                completed=True,
                message=result["message"],
                result=result,
            )
            append_task_log(task_id, "Teste VPN", result["message"], "error")
            return result

        group_name = group.name or "Grupo"
        append_task_log(task_id, group_name, "Iniciando teste de VPN do grupo.", "info")
        update_task_meta(
            task_id,
            status="running",
            progress=10,
            completed=False,
            message="Validando configuracao da VPN...",
        )

        if not group.uses_vpn:
            result = {
                "ok": False,
                "group_id": str(group.id),
                "message": "Grupo sem VPN habilitada.",
            }
            update_task_meta(
                task_id,
                status="failed",
                progress=100,
                completed=True,
                message=result["message"],
                result=result,
            )
            append_task_log(task_id, group_name, result["message"], "warning")
            return result

        conn_name = vpn_service.connect_group_vpn(group, logger=None)
        append_task_log(task_id, group_name, f"VPN conectada com sucesso ({conn_name}).", "success")
        update_task_meta(
            task_id,
            status="running",
            progress=70,
            completed=False,
            message="VPN conectada. Validando encerramento limpo...",
        )

        vpn_service.disconnect_group_vpn(group, logger=None)
        append_task_log(task_id, group_name, "VPN desconectada com sucesso.", "success")

        result = {
            "ok": True,
            "group_id": str(group.id),
            "connection_name": conn_name,
            "message": "VPN conectou e desconectou com sucesso.",
        }
        update_task_meta(
            task_id,
            status="success",
            progress=100,
            completed=True,
            message=result["message"],
            result=result,
        )
        return result
    except VpnError as exc:
        message = str(exc)
        update_task_meta(
            task_id,
            status="failed",
            progress=100,
            completed=True,
            message=message,
            result={"ok": False, "group_id": str(group_id), "message": message},
        )
        append_task_log(task_id, "Teste VPN", message, "error")
        return {"ok": False, "group_id": str(group_id), "message": message}
    except Exception as exc:
        logger.exception("Erro ao testar VPN do grupo %s", group_id)
        message = f"Erro ao testar VPN: {exc}"
        update_task_meta(
            task_id,
            status="failed",
            progress=100,
            completed=True,
            message=message,
            result={"ok": False, "group_id": str(group_id), "message": message},
        )
        append_task_log(task_id, "Teste VPN", message, "error")
        return {"ok": False, "group_id": str(group_id), "message": message}
    finally:
        db.close()


@celery_app.task(bind=True, queue='vpn_queue')
def run_group_jump_host_diagnostic_task(self, group_id: str, device_id: str | None = None):
    from app.models.device_group import DeviceGroup
    from app.services.realtime_backup_logs import append_task_log, update_task_meta

    task_id = str(self.request.id)
    db = SessionLocal()
    try:
        group = db.query(DeviceGroup).filter(DeviceGroup.id == group_id).first()
        if not group:
            result = {"ok": False, "group_id": str(group_id), "message": f"Grupo {group_id} nao encontrado."}
            update_task_meta(task_id, status="failed", progress=100, completed=True, message=result["message"], result=result)
            append_task_log(task_id, "Teste Jump Host", result["message"], "error")
            return result

        update_task_meta(
            task_id,
            status="running",
            progress=20,
            completed=False,
            message="Validando alcance, login SSH e shell no Jump Host...",
        )
        append_task_log(task_id, group.name or "Grupo", "Iniciando teste do Jump Host.", "info")

        health_state = jump_host_service.run_health_check(str(group.tenant_id), group)
        tcp_ok = bool(health_state.get("tcp_ok"))
        ssh_ok = bool(health_state.get("ssh_ok"))
        shell_ok = bool(health_state.get("shell_ok"))
        status = str(health_state.get("status") or "unknown")

        append_task_log(
            task_id,
            group.name or "Grupo",
            f"Conectividade TCP: {'ok' if tcp_ok else 'falhou'}.",
            "success" if tcp_ok else "warning",
        )
        append_task_log(
            task_id,
            group.name or "Grupo",
            f"Login SSH: {'ok' if ssh_ok else 'falhou'}.",
            "success" if ssh_ok else "warning",
        )
        append_task_log(
            task_id,
            group.name or "Grupo",
            f"Shell remoto Linux: {'ok' if shell_ok else 'falhou'}.",
            "success" if shell_ok else "warning",
        )

        category = "ok" if shell_ok else str(health_state.get("last_failure_category") or status or "connectivity_failed")
        recommendation = (
            "Jump Host acessivel com login SSH e shell operacional."
            if shell_ok
            else recommendation_for_category(category)
        )
        message = (
            "Jump Host validado com sucesso."
            if shell_ok
            else str(health_state.get("last_failure_message") or recommendation)
        )
        result = {
            "ok": shell_ok,
            "group_id": str(group.id),
            "category": category,
            "recommendation": recommendation,
            "message": message,
            "health_state": health_state,
            "steps": [
                {"title": "Conectividade TCP", "status": "success" if tcp_ok else "failed", "message": "Porta do Jump Host acessivel." if tcp_ok else "Nao foi possivel abrir socket TCP ate o Jump Host."},
                {"title": "Login SSH", "status": "success" if ssh_ok else "failed", "message": "Autenticacao SSH concluida." if ssh_ok else "Nao foi possivel autenticar via SSH no Jump Host."},
                {"title": "Shell Linux", "status": "success" if shell_ok else "failed", "message": "Shell remoto respondeu ao comando de validacao." if shell_ok else "Shell remoto nao respondeu como esperado."},
            ],
        }
        update_task_meta(
            task_id,
            status="success" if shell_ok else "failed",
            progress=100,
            completed=True,
            message=message,
            result=result,
        )
        append_task_log(
            task_id,
            group.name or "Grupo",
            recommendation,
            "success" if shell_ok else "warning",
        )
        return result
    except Exception as exc:
        logger.exception("Erro ao testar Jump Host do grupo %s", group_id)
        message = f"Erro ao testar Jump Host: {exc}"
        update_task_meta(
            task_id,
            status="failed",
            progress=100,
            completed=True,
            message=message,
            result={"ok": False, "group_id": str(group_id), "message": message},
        )
        append_task_log(task_id, "Teste Jump Host", message, "error")
        return {"ok": False, "group_id": str(group_id), "message": message}
    finally:
        db.close()


@celery_app.task(bind=True, queue='vpn_queue')
def run_device_connection_audit_task(self, device_id: str, bulk_task_id: str = None):
    """
    Executa auditoria de acesso de 1 dispositivo:
    1) ping
    2) login (somente se ping responder)

    Classificacoes:
    - no_ping
    - ping_ok_login_fail
    - ready
    """
    from app.services.connection_test_service import connection_test_service
    from app.services.realtime_backup_logs import append_task_log, update_task_meta

    task_id = str(self.request.id)
    try:
        if _should_stop_now(bulk_task_id):
            stopped = {
                "check_type": "connection_audit",
                "device_id": str(device_id),
                "ok": False,
                "ping_ok": False,
                "login_ok": False,
                "classification": "ping_ok_login_fail",
                "message": "Teste interrompido por solicitacao de parada.",
                "protocol": "unknown",
                "elapsed_ms": 0,
            }
            update_task_meta(
                task_id,
                status="stopped",
                progress=100,
                completed=True,
                message=stopped["message"],
                result=stopped,
            )
            append_task_log(task_id, "Sistema", stopped["message"], "warning")
            return stopped

        device = _load_device_for_connection_audit(device_id)
        if not device:
            result = {
                "check_type": "connection_audit",
                "device_id": str(device_id),
                "ok": False,
                "ping_ok": False,
                "login_ok": False,
                "classification": "no_ping",
                "message": "Dispositivo nao encontrado.",
                "protocol": "unknown",
                "elapsed_ms": 0,
            }
            update_task_meta(
                task_id,
                status="failed",
                progress=100,
                completed=True,
                message=result["message"],
                result=result,
            )
            append_task_log(task_id, "Sistema", result["message"], "error")
            return result

        device_name = device.name or "Dispositivo"
        protocol = "telnet" if device.use_telnet else "ssh"
        update_task_meta(
            task_id,
            status="running",
            progress=15,
            completed=False,
            message="Testando conectividade de rede (ping)...",
        )
        append_task_log(task_id, device_name, "Iniciando teste de ping.", "info")

        started = time.monotonic()
        uses_vpn = bool(device.group and uses_vpn_tunnel(device.group, device=device))
        vpn_ctx = None
        vpn_logger = None
        if uses_vpn:
            from app.services.backup_executor import BackupLogger
            from app.services.vpn_service import vpn_service
            vpn_logger = BackupLogger(device.name, verbose=False)
            vpn_ctx = vpn_service.vpn_session(device.group, logger=vpn_logger)
            vpn_ctx.__enter__()

        ping_ok = bool(MonitorService.ping_device(device.ip_address))
        now_iso = datetime.utcnow().isoformat() + "Z"
        extra_params = dict(device.extra_parameters or {})
        extra_params["connection_test_last_at"] = now_iso
        extra_params["connection_test_ping_ok"] = ping_ok
        extra_params["connection_test_login_ok"] = False
        extra_params["connection_test_protocol"] = protocol
        current_connection_status = "online" if ping_ok else "offline"

        if _should_stop_now(bulk_task_id):
            stopped = {
                "check_type": "connection_audit",
                "device_id": str(device.id),
                "ok": False,
                "ping_ok": True,
                "login_ok": False,
                "classification": "ping_ok_login_fail",
                "message": "Teste interrompido por solicitacao de parada.",
                "protocol": protocol,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
            extra_params["connection_test_group"] = "ping_ok_login_fail"
            extra_params["connection_test_message"] = stopped["message"]
            _persist_connection_audit_state(
                device_id=str(device.id),
                extra_parameters=extra_params,
                last_connection_status=current_connection_status,
            )
            update_task_meta(
                task_id,
                status="stopped",
                progress=100,
                completed=True,
                message=stopped["message"],
                result=stopped,
            )
            append_task_log(task_id, device_name, stopped["message"], "warning")
            return stopped

        if ping_ok:
            current_connection_status = "online"
            update_task_meta(
                task_id,
                status="running",
                progress=55,
                completed=False,
                message="Ping OK. Testando login/acesso...",
            )
            append_task_log(task_id, device_name, "Ping respondeu. Iniciando teste de login.", "info")
        else:
            current_connection_status = "offline"
            update_task_meta(
                task_id,
                status="running",
                progress=55,
                completed=False,
                message="Ping sem resposta. Validando porta/login para evitar falso negativo...",
            )
            append_task_log(
                task_id,
                device_name,
                "Ping sem resposta. Tentando validacao por porta/login (ICMP pode estar bloqueado).",
                "warning",
            )

        service_result = connection_test_service.diagnose_access_chain(
            device=device,
            group=device.group,
            manage_vpn=False,
        )
        connection_result = {
            "success": bool(service_result.get("ok")),
            "message": service_result.get("message"),
            "protocol": service_result.get("protocol"),
            "elapsed_ms": int(service_result.get("elapsed_ms") or 0),
            "tcp_ok": bool(service_result.get("tcp_ok")),
            "jump_host_ok": bool(service_result.get("jump_host_ok")),
            "route_ok": bool(service_result.get("route_ok")),
            "failure_category": str(service_result.get("category") or ""),
            "steps": service_result.get("steps") or [],
        }
        login_ok = bool(connection_result.get("success"))
        tcp_ok = bool(connection_result.get("tcp_ok"))
        if login_ok:
            classification = "ready"
            current_connection_status = "online"
        elif ping_ok or tcp_ok:
            classification = "ping_ok_login_fail"
        else:
            classification = "no_ping"
            current_connection_status = "offline"

        extra_params["connection_test_group"] = classification
        extra_params["connection_test_login_ok"] = login_ok
        extra_params["connection_test_tcp_ok"] = bool(tcp_ok)
        extra_params["connection_test_jump_host_ok"] = bool(connection_result.get("jump_host_ok"))
        extra_params["connection_test_route_ok"] = bool(connection_result.get("route_ok"))
        extra_params["connection_test_failure_category"] = connection_result.get("failure_category")
        extra_params["connection_test_steps"] = connection_result.get("steps")
        extra_params["connection_test_recommendation"] = recommendation_for_category(
            connection_result.get("failure_category"),
            getattr(device, "ip_address", None),
        )
        extra_params["connection_test_message"] = connection_result.get("message")
        extra_params["connection_test_elapsed_ms"] = int(connection_result.get("elapsed_ms") or 0)
        _persist_connection_audit_state(
            device_id=str(device.id),
            extra_parameters=extra_params,
            last_connection_status=current_connection_status,
        )

        result = {
            "check_type": "connection_audit",
            "device_id": str(device.id),
            "ok": login_ok,
            "ping_ok": ping_ok,
            "login_ok": login_ok,
            "classification": classification,
            "message": connection_result.get("message"),
            "protocol": connection_result.get("protocol") or protocol,
            "elapsed_ms": int(connection_result.get("elapsed_ms") or 0),
            "failure_category": connection_result.get("failure_category"),
            "jump_host_ok": bool(connection_result.get("jump_host_ok")),
            "route_ok": bool(connection_result.get("route_ok")),
            "steps": connection_result.get("steps") or [],
            "recommendation": extra_params.get("connection_test_recommendation"),
        }
        if login_ok:
            update_task_meta(
                task_id,
                status="success",
                progress=100,
                completed=True,
                message=(
                    "Ping e login validados com sucesso."
                    if ping_ok
                    else "Ping sem resposta, mas login validado com sucesso."
                ),
                result=result,
            )
            append_task_log(
                task_id,
                device_name,
                "Ping + login OK." if ping_ok else "Ping sem resposta, mas login OK.",
                "success",
            )
        else:
            if classification == "no_ping":
                if device.group and uses_jump_host(device.group, device=device):
                    status_message = "Sem resposta ao ping e sem acesso validado via Jump Host."
                else:
                    status_message = "Sem resposta ao ping e sem acesso na porta de gerencia."
                log_message = status_message
            elif ping_ok:
                status_message = f"Ping OK, login falhou: {connection_result.get('message')}"
                log_message = status_message
            else:
                status_message = f"Ping sem resposta, porta acessivel, login falhou: {connection_result.get('message')}"
                log_message = status_message
            update_task_meta(
                task_id,
                status="success",
                progress=100,
                completed=True,
                message=status_message,
                result=result,
            )
            append_task_log(
                task_id,
                device_name,
                log_message,
                "warning",
            )
        return result
    except Exception as exc:
        logger.exception("Erro ao executar auditoria de conexao do dispositivo %s", device_id)
        result = {
            "check_type": "connection_audit",
            "device_id": str(device_id),
            "ok": False,
            "ping_ok": False,
            "login_ok": False,
            "classification": "ping_ok_login_fail",
            "message": str(exc),
            "protocol": "unknown",
            "elapsed_ms": 0,
            "error": str(exc),
        }
        update_task_meta(
            task_id,
            status="failed",
            progress=100,
            completed=True,
            message=f"Erro na auditoria: {exc}",
            error=str(exc),
            result=result,
        )
        append_task_log(task_id, "Sistema", f"Erro na auditoria: {exc}", "error")
        return result
    finally:
        try:
            if 'vpn_ctx' in locals() and vpn_ctx is not None:
                vpn_ctx.__exit__(None, None, None)
        except Exception:
            pass

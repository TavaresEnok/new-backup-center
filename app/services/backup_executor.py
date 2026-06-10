"""
Backup Executor Service

Este serviÃ§o executa backups usando os scripts especializados do sistema legado.
Cada tipo de equipamento tem seu prÃ³prio script com a lÃ³gica de conexÃ£o e coleta.
"""

import os
import sys
import base64
import importlib.util
import hashlib
import inspect
import logging
import json
import time
from contextlib import AbstractContextManager
from datetime import datetime
from io import StringIO
from typing import Optional, Dict, Any, Tuple

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import decrypt_password
from app.models import Device, DeviceType, DeviceGroup, Backup, BackupStatus, Notification, NotificationType, User, UserRole
from app.services.vpn_service import vpn_service, VpnError
from app.services.realtime_backup_logs import append_task_log
from app.services.plan_limits_service import PlanLimitsService
from app.services.connection_mode import uses_vpn_tunnel, uses_jump_host
from app.services.backup_diagnostics import (
    classify_failure,
    failure_label,
    validate_backup_integrity,
)
from app.services.backup_observability import inc_counter, observe_histogram
from app.services.network_precheck import run_network_precheck
from app.services.tracing import traced_span
from app.scripts.backup_scripts.script_helpers import (
    configure_paramiko_host_key_policy,
    ssh_strict_host_key_checking_enabled,
)
from sqlalchemy.exc import DBAPIError, OperationalError

try:
    import paramiko
except Exception:  # pragma: no cover
    paramiko = None

try:
    from cryptography.hazmat.primitives import serialization
except Exception:  # pragma: no cover
    serialization = None


class _NetmikoJumpHostPatcher(AbstractContextManager):
    """
    Injeta suporte a Jump Host em scripts Netmiko legados sem alterar cada script.
    """

    def __init__(self, scripts_dir: str, jump_host: Optional[Dict[str, Any]], logger: "BackupLogger"):
        self.scripts_dir = os.path.abspath(scripts_dir)
        self.jump_host = jump_host or {}
        self.logger = logger
        self._original_connect_handler: Dict[Any, Any] = {}
        self._primary_connect_handler = None
        self._jump_client = None

    def __enter__(self):
        # Removido o early_exit: agora o patcher atuara como um injetor global de Timeouts
        # para Netmiko, cobrindo tanto conexoes jump_host quanto conexoes DIRETAS!

        jump_enabled = self._is_enabled()
        patched = 0
        for module in list(sys.modules.values()):
            module_path = os.path.abspath(getattr(module, "__file__", "") or "")
            if not module_path.startswith(self.scripts_dir):
                continue
            handler = getattr(module, "ConnectHandler", None)
            if not callable(handler):
                continue
            if module in self._original_connect_handler:
                continue
            self._original_connect_handler[module] = handler
            if self._primary_connect_handler is None:
                self._primary_connect_handler = handler
            setattr(module, "ConnectHandler", self._patched_connect_handler)
            patched += 1

        if patched:
            if jump_enabled:
                self.logger.info(
                    f"Jump Host habilitado para scripts Netmiko ({patched} modulos)."
                )
            else:
                self.logger.info(
                    f"Patcher Netmiko habilitado (timeouts globais, sem Jump Host) em {patched} modulos."
                )
        return self

    def __exit__(self, exc_type, exc, tb):
        for module, original in self._original_connect_handler.items():
            try:
                setattr(module, "ConnectHandler", original)
            except Exception:
                logging.getLogger(__name__).exception("Falha ao restaurar ConnectHandler em %s", module)
        self._original_connect_handler.clear()
        self._primary_connect_handler = None
        self._close_jump_client()
        return False

    def _is_enabled(self) -> bool:
        return bool(
            self.jump_host
            and self.jump_host.get("host")
            and self.jump_host.get("username")
            and paramiko is not None
        )

    def _load_private_key(self, raw_key: Optional[str]):
        if not raw_key or paramiko is None:
            return None

        raw_key = str(raw_key).strip()
        candidates = [raw_key]
        normalized = self._normalize_private_key(raw_key)
        if normalized and normalized != raw_key:
            candidates.insert(0, normalized)
            self.logger.info("Chave do Jump Host convertida de formato bruto/base64 para PEM.")

        for candidate in candidates:
            for cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
                try:
                    return cls.from_private_key(StringIO(candidate))
                except Exception:
                    continue
        return None

    @staticmethod
    def _wrap_pem(header: str, body: str) -> str:
        body = "".join((body or "").split())
        chunks = [body[i : i + 64] for i in range(0, len(body), 64)]
        return f"-----BEGIN {header}-----\n" + "\n".join(chunks) + f"\n-----END {header}-----\n"

    def _normalize_private_key(self, raw_key: str) -> Optional[str]:
        if not raw_key or "BEGIN " in raw_key:
            return raw_key

        compact = "".join(raw_key.split())
        if not compact:
            return None

        padding = "=" * ((4 - len(compact) % 4) % 4)
        try:
            decoded = base64.b64decode(compact + padding, validate=True)
        except Exception:
            return None

        # Algumas chaves foram salvas como DER base64 puro, sem cabecalho PEM.
        if serialization is not None:
            try:
                private_key = serialization.load_der_private_key(decoded, password=None)
                return private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode()
            except Exception:
                pass

        # Fallback simples: tenta tratar o blob base64 como PKCS#8 PEM.
        return self._wrap_pem("PRIVATE KEY", compact)

    def _close_jump_client(self):
        if self._jump_client:
            try:
                self._jump_client.close()
            except Exception:
                pass
            self._jump_client = None

    def _ensure_jump_client(self, timeout: int):
        if self._jump_client:
            transport = self._jump_client.get_transport()
            if transport and transport.is_active():
                return
            self._close_jump_client()

        jump_pkey = self._load_private_key(self.jump_host.get("key"))
        retries = max(1, int(os.getenv("JUMP_HOST_CONNECT_RETRIES", "3") or 3))
        last_error = None
        for attempt in range(1, retries + 1):
            client = configure_paramiko_host_key_policy(paramiko.SSHClient())
            try:
                client.connect(
                    hostname=self.jump_host.get("host"),
                    port=int(self.jump_host.get("port") or 22),
                    username=self.jump_host.get("username"),
                    password=self.jump_host.get("password"),
                    pkey=jump_pkey,
                    timeout=timeout,
                    auth_timeout=timeout,
                    banner_timeout=timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
                transport = client.get_transport()
                if transport:
                    transport.set_keepalive(30)
                self._jump_client = client
                return
            except Exception as exc:
                last_error = exc
                try:
                    client.close()
                except Exception:
                    pass
                if attempt < retries:
                    self.logger.warning(
                        "Falha ao conectar no Jump Host (tentativa %s/%s). Retentando...",
                        attempt,
                        retries,
                    )
                    time.sleep(1.0 * attempt)
        if last_error:
            raise last_error

    def _open_jump_channel(self, transport, target_host: str, target_port: int, timeout: int):
        retries = max(1, int(os.getenv("JUMP_HOST_CHANNEL_RETRIES", "2") or 2))
        last_error = None
        for attempt in range(1, retries + 1):
            try:
                return transport.open_channel(
                    "direct-tcpip",
                    (target_host, target_port),
                    ("127.0.0.1", 0),
                    timeout=float(timeout),
                )
            except Exception as exc:
                last_error = exc
                if attempt < retries:
                    self.logger.warning(
                        "Falha ao abrir canal SSH via Jump Host para %s:%s (tentativa %s/%s). Retentando...",
                        target_host,
                        target_port,
                        attempt,
                        retries,
                    )
                    self._close_jump_client()
                    self._ensure_jump_client(timeout=timeout)
                    transport = self._jump_client.get_transport()
                    time.sleep(0.8 * attempt)
        if last_error:
            raise last_error

    def _patched_connect_handler(self, *args, **kwargs):
        # [INJECAO GLOBAL DE TIMEOUTS DO BACKUP CENTER]
        # Resolve 100% dos erros `Error reading SSH protocol banner` nas OLTs Huawei e MikroTik CCR.
        # Aplica a injecao independente de usar Jump Host ou Conexao Direta.
        kwargs.setdefault("banner_timeout", 45)
        kwargs.setdefault("auth_timeout", 35)
        device_type = str(kwargs.get("device_type") or "").lower()
        if ssh_strict_host_key_checking_enabled() and not device_type.endswith("_telnet"):
            kwargs.setdefault("ssh_strict", True)
            kwargs.setdefault("system_host_keys", True)
        
        # Garante que conn_timeout seja generoso caso o hardware demore a aceitar chaves lentas.
        conn_timeout = kwargs.get("conn_timeout") or kwargs.get("timeout") or 0
        if int(conn_timeout) < 35:
            kwargs["conn_timeout"] = 45

        # Mantem compatibilidade caso algum script ja passe sock manualmente.
        if kwargs.get("sock") is not None or not self._is_enabled():
            return self._call_original(*args, **kwargs)

        target_host = kwargs.get("host")
        target_port = int(kwargs.get("port") or 22)
        if not target_host:
            return self._call_original(*args, **kwargs)

        jump_host = str(self.jump_host.get("host") or "").strip().lower()
        if jump_host and str(target_host).strip().lower() == jump_host:
            self.logger.info(
                f"Destino {target_host}:{target_port} coincide com o Jump Host; usando conexao direta."
            )
            return self._call_original(*args, **kwargs)

        timeout = int(kwargs.get("conn_timeout") or kwargs.get("timeout") or 30)
        self._ensure_jump_client(timeout=timeout)

        transport = self._jump_client.get_transport()
        channel = self._open_jump_channel(transport, target_host, target_port, timeout)
        patched_kwargs = dict(kwargs)
        patched_kwargs["sock"] = channel
        try:
            return self._call_original(*args, **patched_kwargs)
        except Exception:
            try:
                channel.close()
            except Exception:
                pass
            raise

    def _call_original(self, *args, **kwargs):
        if callable(self._primary_connect_handler):
            return self._primary_connect_handler(*args, **kwargs)
        raise RuntimeError("ConnectHandler original nao encontrado para patch de Jump Host.")


class BackupLogger:
    """Logger centralizado para operaÃ§Ãµes de backup."""
    
    def __init__(self, device_name: str, verbose: bool = True, task_id: Optional[str] = None):
        self.device_name = device_name
        self.verbose = verbose
        self.task_id = task_id
        self.logs = []

    @staticmethod
    def _normalize_message(message: Any, args: tuple, kwargs: dict) -> str:
        text = str(message)
        if args:
            try:
                text = text % args
            except Exception:
                text = " ".join([text, *[str(arg) for arg in args]])
        if kwargs:
            try:
                text = text % kwargs
            except Exception:
                pairs = " ".join(f"{k}={v}" for k, v in kwargs.items())
                text = f"{text} {pairs}".strip()
        try:
            from app.utils.log_sanitizer import sanitize_operational_message

            return sanitize_operational_message(text)
        except Exception:
            return text

    def log(self, message: Any, level: str = 'info', *args, **kwargs):
        message = self._normalize_message(message, args, kwargs)
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] [{level.upper()}] [{self.device_name}] {message}"
        self.logs.append({'level': level, 'message': message, 'timestamp': timestamp})
        if self.verbose:
            logger = logging.getLogger(__name__)
            level_map = {
                'info': logging.INFO,
                'success': logging.INFO,
                'warning': logging.WARNING,
                'error': logging.ERROR,
            }
            logger.log(level_map.get(level, logging.INFO), log_entry)
        if self.task_id:
            append_task_log(self.task_id, self.device_name, message, level)

    def info(self, message: Any, *args, **kwargs):
        self.log(message, 'info', *args, **kwargs)

    def success(self, message: Any, *args, **kwargs):
        self.log(message, 'success', *args, **kwargs)

    def error(self, message: Any, *args, **kwargs):
        self.log(message, 'error', *args, **kwargs)

    def warning(self, message: Any, *args, **kwargs):
        self.log(message, 'warning', *args, **kwargs)


def _truthy_env(name: str, default: str = "0") -> bool:
    return str(os.getenv(name, default) or "").strip().lower() in {"1", "true", "on", "yes"}


def _is_mikrotik_device(device_type: DeviceType | None) -> bool:
    if not device_type:
        return False
    name = str(getattr(device_type, "name", "") or "").strip().lower()
    script_name = str(getattr(device_type, "script_name", "") or "").strip().lower()
    return (
        "mikrotik" in name
        or "routeros" in name
        or "mikrotik" in script_name
        or "routeros" in script_name
    )


def _filter_script_kwargs(backup_fn, kwargs: Dict[str, Any]) -> Tuple[Dict[str, Any], list[str]]:
    """Keep older backup scripts runnable when the executor adds parameters."""
    try:
        signature = inspect.signature(backup_fn)
    except (TypeError, ValueError):
        return kwargs, []

    if any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    ):
        return kwargs, []

    allowed = {
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind in {
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        }
    }
    dropped = sorted(key for key in kwargs if key not in allowed)
    return {key: value for key, value in kwargs.items() if key in allowed}, dropped


def _emit_backup_event(event_name: str, **payload):
    data = {"event": str(event_name or "unknown"), "ts": datetime.utcnow().isoformat() + "Z"}
    for key, value in (payload or {}).items():
        if value is None:
            continue
        data[str(key)] = value
    try:
        logging.getLogger(__name__).info(
            "backup_event %s",
            json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
        )
    except Exception:
        pass


class BackupExecutor:
    """
    Executa backups usando os scripts especializados.
    """
    
    SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'backup_scripts')
    BACKUP_BASE_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'storage', 'backups')
    
    def __init__(self):
        self._script_cache = {}
        self._script_cache_mtime = {}
        self._script_load_errors = {}
    
    def _load_script(self, script_name: str) -> Optional[Any]:
        """
        Carrega dinamicamente um script de backup.
        """
        script_path = os.path.join(self.SCRIPTS_DIR, script_name)
        script_mtime = os.path.getmtime(script_path) if os.path.exists(script_path) else None

        if script_name in self._script_cache and self._script_cache_mtime.get(script_name) == script_mtime:
            return self._script_cache[script_name]
        
        # Garantir que imports absolutos (ex: import script_helpers) funcionem
        if self.SCRIPTS_DIR not in sys.path:
            sys.path.append(self.SCRIPTS_DIR)
        
        if not os.path.exists(script_path):
            self._script_load_errors[script_name] = "Arquivo nao encontrado."
            self._script_cache.pop(script_name, None)
            self._script_cache_mtime.pop(script_name, None)
            return None
        
        try:
            module_name = script_name.replace('.py', '')
            spec = importlib.util.spec_from_file_location(module_name, script_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            self._script_cache[script_name] = module
            self._script_cache_mtime[script_name] = script_mtime
            self._script_load_errors.pop(script_name, None)
            return module
        except Exception as exc:
            sys.modules.pop(script_name.replace('.py', ''), None)
            self._script_cache.pop(script_name, None)
            self._script_cache_mtime.pop(script_name, None)
            self._script_load_errors[script_name] = str(exc)
            logging.getLogger(__name__).exception("failed to load script %s", script_name)
            return None
    
    def _get_backup_path(self, tenant_slug: str, group_name: str, device_name: str) -> str:
        """
        Retorna o caminho do diretÃ³rio de backup para um dispositivo.
        Estrutura: storage/backups/{tenant_slug}/{group_name}/{device_name}/
        """
        # Sanitiza nomes para uso em paths
        def sanitize(name: str) -> str:
            if not name:
                return "unnamed"
            return "".join(c for c in name if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')
        
        path = os.path.join(
            self.BACKUP_BASE_DIR,
            sanitize(tenant_slug),
            sanitize(group_name),
            sanitize(device_name)
        )
        os.makedirs(path, exist_ok=True)
        return path
    
    def execute_backup(
        self,
        device: Device,
        device_type: DeviceType,
        group: Optional[DeviceGroup] = None,
        tenant_slug: str = "default",
        manage_vpn: bool = True,
        task_id: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Executa backup de um dispositivo.
        
        Returns:
            Tuple[bool, str, Optional[str]]: (sucesso, mensagem, caminho_arquivo)
        """
        logger = BackupLogger(device.name, task_id=task_id)
        
        # Verifica se tem script configurado
        if not device_type or not device_type.script_name:
            return False, "Tipo de dispositivo sem script configurado", None
        
        # Carrega o script
        script = self._load_script(device_type.script_name)
        if not script:
            load_error = self._script_load_errors.get(device_type.script_name)
            if load_error:
                return False, f"Falha ao carregar script {device_type.script_name}: {load_error}", None
            return False, f"Script {device_type.script_name} nao encontrado", None
        
        # Verifica se o script tem a funcao realizar_backup
        if not hasattr(script, 'realizar_backup'):
            return False, f"Script {device_type.script_name} nao tem funcao realizar_backup", None
        
        # Prepara argumentos
        group_name = group.name if group else "Sem Grupo"
        backup_dir = self._get_backup_path(tenant_slug, group_name, device.name)
        
        # Descriptografa senha
        try:
            password = decrypt_password(device.password_encrypted)
        except Exception as exc:
            err_name = getattr(getattr(exc, "__class__", None), "__name__", "") or "erro_desconhecido"
            msg = f"Falha ao descriptografar credencial do dispositivo ({err_name}). Regrave a senha do equipamento."
            logger.error(msg)
            return False, msg, None
        parametros = {}
        if device.extra_parameters:
            parametros.update(device.extra_parameters)
        parametros.setdefault('password', password)
        # Compatibilidade com scripts legados que leem a flag dentro de `parametros`.
        parametros['use_telnet'] = bool(device.use_telnet)
        
        # Monta argumentos para o script.
        # Normaliza host/usuario (strip) defensivamente no ponto de uso: cobre dispositivos
        # legados ja cadastrados com espacos/quebras de linha acidentais, que falhavam
        # conexao/autenticacao. A senha NUNCA e normalizada (pode ter espacos significativos).
        kwargs = {
            'ip': str(device.ip_address or "").strip(),
            'porta': device.port,
            'usuario': str(device.username or "").strip(),
            'password': password,
            'nome_provedor': group_name,
            'nome_tipo_equip': device_type.name,
            'nome_dispositivo': device.name,
            'backup_dir': backup_dir,
            'backup_base_path': backup_dir,
            'parametros': parametros,
            'logger': logger,
            'task_id': task_id,
        }
        
        # Adiciona parametros extras se existirem
        if device.extra_parameters:
            kwargs.update(device.extra_parameters)
        
        # Adiciona flag de telnet se necessário
        if device.use_telnet:
            # Alguns scripts leem `use_telnet`, outros `usar_telnet`.
            kwargs['use_telnet'] = True
            kwargs['usar_telnet'] = True
        
        # Adiciona parâmetros de Jump Host se o grupo usar.
        # O modo de conexão (Jump Host, VPN, direto) é definido pelo analista no cadastro
        # do grupo/dispositivo e deve ser respeitado para qualquer tipo de equipamento.
        if group and uses_jump_host(group, device=device) and group.jump_host:
            logger.info(f"Usando Jump Host: {group.jump_host}:{group.jump_port or 22}")
            jump_password = None
            jump_key = None
            if group.jump_password_encrypted:
                try:
                    jump_password = decrypt_password(group.jump_password_encrypted)
                except Exception as exc:
                    err_name = getattr(getattr(exc, "__class__", None), "__name__", "") or "erro_desconhecido"
                    msg = f"Falha ao descriptografar senha do Jump Host ({err_name}). Regrave a senha do grupo."
                    logger.error(msg)
                    return False, msg, None
            if group.jump_key_encrypted:
                try:
                    jump_key = decrypt_password(group.jump_key_encrypted)
                except Exception as exc:
                    err_name = getattr(getattr(exc, "__class__", None), "__name__", "") or "erro_desconhecido"
                    msg = f"Falha ao descriptografar chave do Jump Host ({err_name}). Regrave a chave do grupo."
                    logger.error(msg)
                    return False, msg, None

            if not group.jump_username:
                msg = "Jump Host configurado sem usuario. Ajuste o grupo antes de executar o backup."
                logger.error(msg)
                return False, msg, None
            if not jump_password and not jump_key:
                msg = "Jump Host sem credencial (senha/chave). Ajuste o grupo antes de executar o backup."
                logger.error(msg)
                return False, msg, None
            
            # Normaliza host/usuario do Jump Host (strip) — espacos acidentais quebravam
            # o comando SSH montado no shell do bastion. Senha/chave ficam intactas.
            jump_host_clean = str(group.jump_host or "").strip()
            jump_username_clean = str(group.jump_username or "").strip()
            kwargs['jump_host'] = {
                'host': jump_host_clean,
                'port': group.jump_port or 22,
                'username': jump_username_clean,
                'password': jump_password,
                'key': jump_key,
            }
            # Também adiciona como parâmetros individuais para compatibilidade
            kwargs['usar_jump_host'] = True
            kwargs['jump_host_ip'] = jump_host_clean
            kwargs['jump_host_porta'] = group.jump_port or 22
            kwargs['jump_host_usuario'] = jump_username_clean
            kwargs['jump_host_senha'] = jump_password
            kwargs['jump_host_chave'] = jump_key
        
        def _execute_script():
            logger.info(f"Iniciando backup...")
            logger.info(f"Tipo: {device_type.name}")
            logger.info(f"Script: {device_type.script_name}")
            script_started = time.monotonic()
            # Marco de relogio de parede usado para validar que o arquivo de backup foi
            # gerado NESTA execucao (ver fallback de "arquivo mais recente" abaixo).
            # Tolerancia de 5s cobre pequeno clock skew/arredondamento de mtime.
            script_started_wall = time.time() - 5
            jump_host_cfg = kwargs.get("jump_host")
            jump_label = (
                f"{jump_host_cfg.get('host')}:{int(jump_host_cfg.get('port') or 22)}"
                if isinstance(jump_host_cfg, dict) and jump_host_cfg.get("host")
                else "direct"
            )
            metric_base_labels = {
                "tenant": str(tenant_slug or "unknown"),
                "device_type": str(device_type.name or "unknown"),
                "script_name": str(device_type.script_name or "unknown"),
                "jump_host": jump_label,
            }

            with traced_span(
                "backup.script.execute",
                attributes={
                    "backup.device_name": str(device.name or ""),
                    "backup.device_ip": str(device.ip_address or ""),
                    "backup.device_port": int(device.port or (23 if device.use_telnet else 22)),
                    "backup.device_type": str(device_type.name or ""),
                    "backup.script_name": str(device_type.script_name or ""),
                    "backup.jump_host": jump_label,
                },
            ) as script_span:
                try:
                    precheck_enabled = _truthy_env("BACKUP_NETWORK_PRECHECK_ENABLED", "1")
                    precheck_fail_fast = _truthy_env("BACKUP_NETWORK_PRECHECK_FAIL_FAST", "1")
                    precheck_timeout = max(1, int(os.getenv("BACKUP_NETWORK_PRECHECK_TIMEOUT_SECONDS", "5") or 5))
                    skip_precheck_for_jump = bool(
                        jump_host_cfg and _truthy_env("BACKUP_NETWORK_PRECHECK_SKIP_FOR_JUMP", "1")
                    )
                    skip_precheck_for_jump_telnet = bool(jump_host_cfg and bool(device.use_telnet))
                    if precheck_enabled and (skip_precheck_for_jump or skip_precheck_for_jump_telnet):
                        if skip_precheck_for_jump_telnet:
                            logger.info(
                                "Precheck de rede ignorado para TELNET via Jump Host; seguindo tentativa real do script."
                            )
                        else:
                            logger.info(
                                "Precheck de rede ignorado para dispositivo via Jump Host; seguindo tentativa real do script."
                            )
                        inc_counter(
                            "backup_precheck_total",
                            labels={
                                **metric_base_labels,
                                "outcome": "skipped_jump_telnet" if skip_precheck_for_jump_telnet else "skipped_jump",
                                "ping_method": "none",
                                "tcp_method": "none",
                            },
                        )
                    elif precheck_enabled:
                        precheck = run_network_precheck(
                            host=str(device.ip_address or ""),
                            port=int(device.port or (23 if device.use_telnet else 22)),
                            timeout_seconds=precheck_timeout,
                            jump_host=jump_host_cfg if isinstance(jump_host_cfg, dict) else None,
                        )
                        observe_histogram(
                            "backup_precheck_duration_seconds",
                            max(0.0, precheck.duration_ms / 1000.0),
                            labels={
                                **metric_base_labels,
                                "result": "tcp_ok" if precheck.tcp_ok else "tcp_fail",
                            },
                        )
                        if precheck.ping_ok and precheck.tcp_ok:
                            precheck_outcome = "ready"
                        elif precheck.tcp_ok:
                            precheck_outcome = "tcp_ok_ping_fail"
                        elif precheck.ping_ok:
                            precheck_outcome = "ping_ok_tcp_fail"
                        else:
                            precheck_outcome = "down"
                        inc_counter(
                            "backup_precheck_total",
                            labels={
                                **metric_base_labels,
                                "outcome": precheck_outcome,
                                "ping_method": precheck.ping_method,
                                "tcp_method": precheck.tcp_method,
                            },
                        )
                        logger.info(
                            "Precheck rede: ping_ok=%s tcp_ok=%s ping_method=%s tcp_method=%s rtt_ms=%s",
                            precheck.ping_ok,
                            precheck.tcp_ok,
                            precheck.ping_method,
                            precheck.tcp_method,
                            precheck.ping_rtt_ms,
                        )
                        if script_span is not None:
                            script_span.set_attribute("backup.precheck_ping_ok", bool(precheck.ping_ok))
                            script_span.set_attribute("backup.precheck_tcp_ok", bool(precheck.tcp_ok))
                            script_span.set_attribute("backup.precheck_ping_method", str(precheck.ping_method or "none"))
                            script_span.set_attribute("backup.precheck_tcp_method", str(precheck.tcp_method or "none"))
                        allow_ignore_jump_tcp_fail = _truthy_env(
                            "BACKUP_NETWORK_PRECHECK_IGNORE_JUMP_TCP_FAIL",
                            "0",
                        )
                        ignore_fail_fast_for_jump_telnet = bool(
                            jump_host_cfg
                            and bool(device.use_telnet)
                            and not precheck.tcp_ok
                            and allow_ignore_jump_tcp_fail
                        )
                        ignore_fail_fast_for_jump = bool(
                            jump_host_cfg
                            and not precheck.tcp_ok
                            and allow_ignore_jump_tcp_fail
                        )
                        if ignore_fail_fast_for_jump_telnet:
                            logger.warning(
                                "Precheck TCP falhou (%s), mas o dispositivo usa TELNET via Jump Host. "
                                "Ignorando fail-fast e seguindo tentativa real do script.",
                                precheck.tcp_method,
                            )
                            inc_counter(
                                "backup_precheck_total",
                                labels={
                                    **metric_base_labels,
                                    "outcome": "tcp_fail_ignored_jump_telnet",
                                    "ping_method": precheck.ping_method,
                                    "tcp_method": precheck.tcp_method,
                                },
                            )
                        if ignore_fail_fast_for_jump and not ignore_fail_fast_for_jump_telnet:
                            logger.warning(
                                "Precheck TCP falhou (%s), mas o dispositivo usa Jump Host. "
                                "Ignorando fail-fast e seguindo tentativa real do script.",
                                precheck.tcp_method,
                            )
                            inc_counter(
                                "backup_precheck_total",
                                labels={
                                    **metric_base_labels,
                                    "outcome": "tcp_fail_ignored_jump",
                                    "ping_method": precheck.ping_method,
                                    "tcp_method": precheck.tcp_method,
                                },
                            )
                        # Retry confirmatorio antes de abortar via fail-fast.
                        # Sob carga do backup em massa, um unico probe TCP curto (2s) pode
                        # falhar por latencia transitoria, abortando um dispositivo que
                        # responderia em 3-5s. So re-testa quando IA abortar — dispositivos
                        # saudaveis (que passam de primeira) nao sao afetados/atrasados.
                        if (
                            precheck_fail_fast
                            and not precheck.tcp_ok
                            and not ignore_fail_fast_for_jump_telnet
                            and not ignore_fail_fast_for_jump
                        ):
                            confirm_retries = max(
                                0, int(os.getenv("BACKUP_NETWORK_PRECHECK_CONFIRM_RETRIES", "1") or 1)
                            )
                            confirm_timeout = max(
                                precheck_timeout,
                                int(os.getenv("BACKUP_NETWORK_PRECHECK_CONFIRM_TIMEOUT_SECONDS", "4") or 4),
                            )
                            for _confirm_attempt in range(confirm_retries):
                                recheck = run_network_precheck(
                                    host=str(device.ip_address or ""),
                                    port=int(precheck.tcp_port or device.port or (23 if device.use_telnet else 22)),
                                    timeout_seconds=confirm_timeout,
                                    jump_host=jump_host_cfg if isinstance(jump_host_cfg, dict) else None,
                                )
                                if recheck.tcp_ok:
                                    precheck = recheck
                                    logger.warning(
                                        "Precheck TCP recuperado na tentativa confirmatoria %d/%d "
                                        "(timeout %ss). Prosseguindo com o backup.",
                                        _confirm_attempt + 1,
                                        confirm_retries,
                                        confirm_timeout,
                                    )
                                    inc_counter(
                                        "backup_precheck_total",
                                        labels={
                                            **metric_base_labels,
                                            "outcome": "tcp_fail_recovered_retry",
                                            "ping_method": recheck.ping_method,
                                            "tcp_method": recheck.tcp_method,
                                        },
                                    )
                                    break

                        if (
                            precheck_fail_fast
                            and not precheck.tcp_ok
                            and not ignore_fail_fast_for_jump_telnet
                            and not ignore_fail_fast_for_jump
                        ):
                            msg = (
                                f"Rede inalcançável ({precheck.tcp_method}): Não foi possível acessar a porta {precheck.tcp_port}. "
                                "Backup abortado via precheck/fail-fast."
                            )
                            logger.error(msg)
                            inc_counter("backup_script_total", labels={**metric_base_labels, "outcome": "precheck_fail"})
                            return False, msg, None

                    # Executa o backup
                    script_kwargs, ignored_kwargs = _filter_script_kwargs(script.realizar_backup, kwargs)
                    if ignored_kwargs:
                        logger.warning(
                            "Script legado sem suporte a parametros adicionais; ignorando: %s.",
                            ", ".join(ignored_kwargs),
                        )
                    with _NetmikoJumpHostPatcher(self.SCRIPTS_DIR, jump_host_cfg, logger):
                        result = script.realizar_backup(**script_kwargs)

                    success = None
                    message = None
                    explicit_path = None
                    if isinstance(result, (tuple, list)):
                        if len(result) > 0:
                            success = bool(result[0])
                        if len(result) > 1:
                            message = result[1]
                        if len(result) > 2:
                            explicit_path = result[2]
                    elif isinstance(result, bool):
                        success = result
                    else:
                        success = bool(result)
                    if message:
                        try:
                            from app.utils.log_sanitizer import sanitize_operational_message

                            message = sanitize_operational_message(message)
                        except Exception:
                            message = str(message)

                    if success:
                        # Prioriza o caminho explicito retornado pelo script.
                        file_path = explicit_path
                        if not file_path:
                            # Fallback: arquivo mais recente do diretorio, mas SOMENTE se foi
                            # gerado nesta execucao. Sem o guard de mtime, um script que retorna
                            # sucesso sem gerar arquivo novo faria o executor pegar um backup
                            # ANTIGO do diretorio e registrar falso sucesso com config desatualizada.
                            candidate_files = sorted(
                                [
                                    os.path.join(backup_dir, f)
                                    for f in os.listdir(backup_dir)
                                    if os.path.isfile(os.path.join(backup_dir, f))
                                ],
                                key=os.path.getmtime,
                                reverse=True,
                            )
                            for candidate in candidate_files:
                                try:
                                    if os.path.getmtime(candidate) >= script_started_wall:
                                        file_path = candidate
                                        break
                                except OSError:
                                    continue
                            if candidate_files and not file_path:
                                logger.warning(
                                    "Script reportou sucesso mas nenhum arquivo novo foi gerado nesta "
                                    "execucao (o mais recente e anterior ao inicio do backup). "
                                    "Tratando como falha para nao registrar backup desatualizado."
                                )

                        if file_path:
                            logger.info("Arquivo de backup gerado; validando integridade...")
                            return True, message or "Backup realizado com sucesso", file_path
                        msg = "Comando executado, mas nenhum arquivo novo foi gerado nesta execucao."
                        logger.error(msg)
                        return False, msg, None
                    # O script especializado normalmente ja emite o erro detalhado no log
                    # do dispositivo. Evita repetir a mesma mensagem logo em seguida.
                    return False, message or "Falha ao realizar backup", None
                except Exception as e:
                    error_msg = str(e)
                    try:
                        from app.utils.log_sanitizer import sanitize_operational_message

                        error_msg = sanitize_operational_message(error_msg)
                    except Exception:
                        pass
                    _low = error_msg.lower()
                    _timeout_markers = ("timed out", "timeout", "authentication timeout", "read timeout")
                    _net_markers = ("unable to connect", "connection refused", "no route to host", "network is unreachable", "tcp connection")
                    if any(m in _low for m in _timeout_markers):
                        from app.scripts.backup_scripts.script_helpers import friendly_failure_message
                        _friendly = friendly_failure_message("TIMEOUT", "Tempo esgotado aguardando resposta do equipamento.")
                        logger.error(f"Erro: {_friendly}")
                        return False, _friendly, None
                    if any(m in _low for m in _net_markers):
                        from app.scripts.backup_scripts.script_helpers import friendly_failure_message
                        _friendly = friendly_failure_message("CONEXAO", error_msg)
                        logger.error(f"Erro: {_friendly}")
                        return False, _friendly, None
                    logger.error(f"Erro: {error_msg}")
                    return False, f"Erro durante backup: {error_msg}", None
                finally:
                    duration_seconds = max(0.0, time.monotonic() - script_started)
                    outcome = "success" if 'success' in locals() and bool(success) else "failed"
                    observe_histogram(
                        "backup_script_duration_seconds",
                        duration_seconds,
                        labels={**metric_base_labels, "outcome": outcome},
                    )
                    inc_counter("backup_script_total", labels={**metric_base_labels, "outcome": outcome})
                    if script_span is not None:
                        script_span.set_attribute("backup.outcome", outcome)
                        script_span.set_attribute("backup.duration_ms", int(duration_seconds * 1000))
                    _emit_backup_event(
                        "backup_script_finished",
                        device_name=device.name,
                        device_ip=device.ip_address,
                        tenant=tenant_slug,
                        group=group_name,
                        jump_host=jump_label,
                        device_type=device_type.name if device_type else None,
                        script_name=device_type.script_name if device_type else None,
                        outcome=outcome,
                        duration_ms=int(duration_seconds * 1000),
                    )

        if group and uses_vpn_tunnel(group, device=device) and manage_vpn:
            try:
                with vpn_service.vpn_session(group, logger=logger):
                    return _execute_script()
            except VpnError as e:
                logger.error(str(e))
                return False, f"Falha ao preparar VPN: {e}", None

        return _execute_script()
    
    def run_backup_for_device_id(
        self,
        device_id: str,
        manage_vpn: bool = True,
        task_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Executa backup para um dispositivo pelo ID.
        """
        db = SessionLocal()
        
        try:
            PlanLimitsService.ensure_schema()
            device = db.query(Device).filter_by(id=device_id).first()
            if not device:
                return False, "Dispositivo nao encontrado"
            
            device_type = db.query(DeviceType).filter_by(id=device.device_type_id).first()
            group = db.query(DeviceGroup).filter_by(id=device.group_id).first() if device.group_id else None
            tenant = device.tenant
            tenant_slug = tenant.slug if tenant else "default"
            # Carrega override de subgrupo antes de fechar a sessao. A coleta via SSH/Telnet
            # pode levar minutos; manter uma transacao do Postgres aberta durante rede faz o
            # idle_in_transaction_session_timeout matar a conexao e gera falhas falsas.
            _ = getattr(device, "subgroup", None)
            db.commit()
            db.close()
            db = None
            
            with traced_span(
                "backup.device.execute",
                attributes={
                    "backup.device_id": str(device.id),
                    "backup.device_name": str(device.name or ""),
                    "backup.device_ip": str(device.ip_address or ""),
                    "backup.device_port": int(device.port or (23 if device.use_telnet else 22)),
                    "backup.device_type": str(device_type.name if device_type else "unknown"),
                    "backup.script_name": str(device_type.script_name if device_type else "unknown"),
                    "backup.group_name": str(group.name if group else "Sem Grupo"),
                    "backup.tenant": str(tenant_slug or "default"),
                },
            ) as backup_span:
                started_at = datetime.utcnow()
                success, message, file_path = self.execute_backup(
                    device=device,
                    device_type=device_type,
                    group=group,
                    tenant_slug=tenant_slug,
                    manage_vpn=manage_vpn,
                    task_id=task_id,
                )
                completed_at = datetime.utcnow()
                if backup_span is not None:
                    backup_span.set_attribute("backup.success", bool(success))
                    backup_span.set_attribute("backup.duration_ms", int((completed_at - started_at).total_seconds() * 1000))
            
            file_size = None
            file_hash = None
            if file_path and os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                hasher = hashlib.sha256()
                with open(file_path, 'rb') as handle:
                    for chunk in iter(lambda: handle.read(8192), b''):
                        hasher.update(chunk)
                file_hash = hasher.hexdigest()

            integrity = None
            if success:
                integrity = validate_backup_integrity(
                    file_path=file_path,
                    device_type_name=(device_type.name if device_type else ""),
                    script_name=(device_type.script_name if device_type else ""),
                )
                if not integrity.get("ok"):
                    success = False
                    message = (
                        f"Falha de integridade do arquivo pós-coleta: {integrity.get('reason') or 'erro de validacao'}."
                    )

            if success and file_size:
                quota_db = SessionLocal()
                try:
                    quota_device = quota_db.query(Device).filter_by(id=device_id).first()
                    quota_tenant = quota_device.tenant if quota_device else None
                    if quota_tenant:
                        quota_check = PlanLimitsService.check_storage_before_backup(quota_db, quota_tenant, file_size)
                        if not quota_check.allowed:
                            success = False
                            message = quota_check.reason
                            if file_path and os.path.exists(file_path):
                                try:
                                    os.remove(file_path)
                                except Exception:
                                    logging.getLogger(__name__).exception(
                                        "Falha ao remover arquivo acima da cota de storage (%s)",
                                        file_path,
                                    )
                            file_path = None
                            file_size = None
                            file_hash = None
                    quota_db.commit()
                except Exception:
                    quota_db.rollback()
                    raise
                finally:
                    quota_db.close()

            if success:
                BackupLogger(device.name, task_id=task_id).success("Arquivo de backup salvo e validado.")

            failure_category = None
            failure_category_label = None
            if not success:
                failure_category = classify_failure(message)
                failure_category_label = failure_label(failure_category)
                
                if not message or message == 'Falha ao realizar backup':
                    message = f"Falha sistêmica classificada como: {failure_category_label}."
            _emit_backup_event(
                "backup_device_finished",
                device_id=str(device.id),
                device_name=device.name,
                tenant=tenant_slug,
                group=(group.name if group else "Sem Grupo"),
                device_type=(device_type.name if device_type else None),
                script_name=(device_type.script_name if device_type else None),
                success=bool(success),
                failure_category=failure_category,
                duration_ms=max(0, int((completed_at - started_at).total_seconds() * 1000)),
            )

            backup_meta = {
                "meta": {
                    "device_type": device_type.name if device_type else None,
                    "script_name": device_type.script_name if device_type else None,
                    "failure_category": failure_category,
                    "failure_label": failure_category_label,
                    "integrity": integrity,
                }
            }

            def _persist_backup_result(db_session):
                device_row = db_session.query(Device).filter_by(id=device_id).first()
                if not device_row:
                    raise RuntimeError("Dispositivo nao encontrado ao persistir resultado do backup.")

                backup = Backup(
                    device_id=device_row.id,
                    status=BackupStatus.SUCCESS if success else BackupStatus.FAILED,
                    error_message=None if success else message,
                    config_data=backup_meta,
                    file_path=file_path,
                    file_size_bytes=file_size,
                    hash_sha256=file_hash,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=max(0, int((completed_at - started_at).total_seconds())),
                )
                db_session.add(backup)

                device_row.last_backup_at = datetime.utcnow()
                device_row.last_backup_status = 'success' if success else 'failure'
                extra = dict(device_row.extra_parameters or {})
                extra["last_backup_integrity_ok"] = bool(integrity.get("ok")) if integrity else bool(success)
                if integrity:
                    extra["last_backup_integrity_reason"] = str(integrity.get("reason") or "")
                if success:
                    extra.pop("last_backup_failure_category", None)
                    extra.pop("last_backup_failure_label", None)
                    extra.pop("last_backup_failure_message", None)
                    extra.pop("last_backup_failure_at", None)
                else:
                    extra["last_backup_failure_category"] = failure_category or "unknown"
                    extra["last_backup_failure_label"] = failure_category_label or "Outros"
                    extra["last_backup_failure_message"] = str(message or "")
                    extra["last_backup_failure_at"] = completed_at.isoformat() + "Z"
                device_row.extra_parameters = extra
                db_session.commit()

                # Notificações não podem impedir o registro do backup.
                if not success and device_row.tenant_id:
                    try:
                        recipients = db_session.query(User).filter(
                            User.tenant_id == device_row.tenant_id,
                            User.role.in_([UserRole.TENANT_OWNER, UserRole.TENANT_ADMIN])
                        ).all()
                        for recipient in recipients:
                            db_session.add(Notification(
                                user_id=recipient.id,
                                type=NotificationType.BACKUP_FAILED,
                                title="Backup falhou",
                                message=f"Dispositivo {device_row.name}: {message}",
                            ))
                        db_session.commit()
                    except Exception:
                        db_session.rollback()
                        logging.getLogger(__name__).exception(
                            "Falha ao registrar notificacao de backup para o dispositivo %s",
                            device_row.id
                        )

            def _is_connection_drop_error(exc: Exception) -> bool:
                if isinstance(exc, (OperationalError, DBAPIError)) and bool(
                    getattr(exc, "connection_invalidated", False)
                ):
                    return True
                text = str(exc or "").lower()
                markers = (
                    "server closed the connection unexpectedly",
                    "connection not open",
                    "connection refused",
                    "could not connect to server",
                    "ssl connection has been closed unexpectedly",
                )
                return any(marker in text for marker in markers)

            db = SessionLocal()
            try:
                _persist_backup_result(db)
            except Exception as persist_exc:
                db.rollback()
                if not _is_connection_drop_error(persist_exc):
                    raise
                logging.getLogger(__name__).warning(
                    "Conexao DB caiu ao persistir backup do dispositivo %s. Tentando nova sessao...",
                    device_id,
                    exc_info=True,
                )
                try:
                    db.close()
                except Exception:
                    pass
                db = SessionLocal()
                _persist_backup_result(db)
            
            return success, message
            
        except Exception as e:
            if db is not None:
                db.rollback()
            return False, str(e)
        finally:
            if db is not None:
                db.close()


# Singleton
backup_executor = BackupExecutor()

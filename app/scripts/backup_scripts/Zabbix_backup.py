import os
import paramiko
import re
import shlex
from typing import Tuple

from netmiko import ConnectHandler

from script_helpers import (
    BackupLogger,
    configure_paramiko_host_key_policy,
    friendly_failure_message,
    prepare_backup_path,
)


ZABBIX_DB_CONF_PATH = "/etc/zabbix/zabbix_server.conf"
ZABBIX_DB_KEYS = ("DBName", "DBUser", "DBPassword")
MIN_REMOTE_DUMP_SIZE = 128
DUMP_STATUS_RE = re.compile(r"__BC_DUMP_STATUS__\s+dump=(\d+)\s+gzip=(\d+)\s+size=(\d+)")


def _normalize_db_type(value: str) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"postgres", "postgresql", "postgre", "postgree", "pgsql"}:
        return "postgres"
    if raw in {"mariadb", "mysql"}:
        return "mariadb"
    return raw


def _is_privileged_prompt(output: str) -> bool:
    text = (output or "").strip()
    return text.endswith("#")


def _become_root(net_connect, secrets, logger) -> bool:
    """Tenta elevar privilegio de forma tolerante para ambientes legados."""
    logger.emit("A obter acesso root...", "info")

    probe = net_connect.send_command_timing(
        "whoami",
        read_timeout=15,
        strip_command=False,
        strip_prompt=False,
    )
    if "root" in (probe or "").lower():
        logger.emit("Sessao ja esta com privilegios de root.", "success")
        return True

    candidates = []
    for item in secrets:
        value = (item or "").strip()
        if value and value not in candidates:
            candidates.append(value)

    for cmd in ("su -", "sudo -s", "sudo su -"):
        try:
            output = net_connect.send_command_timing(
                cmd,
                read_timeout=20,
                strip_command=False,
                strip_prompt=False,
            )

            # Alguns hosts voltam direto para prompt privilegiado.
            if _is_privileged_prompt(output):
                logger.emit("Privilegios de root obtidos com sucesso.", "success")
                return True

            lower = (output or "").lower()
            if "password" in lower or "senha" in lower:
                for secret in candidates:
                    ans = net_connect.send_command_timing(
                        secret,
                        read_timeout=20,
                        strip_command=False,
                        strip_prompt=False,
                    )
                    if _is_privileged_prompt(ans):
                        logger.emit("Privilegios de root obtidos com sucesso.", "success")
                        return True
                    if "sorry" in (ans or "").lower() or "incorrect" in (ans or "").lower():
                        continue
        except Exception:
            continue

    logger.emit("Nao foi possivel obter root; tentando continuar sem elevacao.", "warning")
    return False


def _parse_zabbix_conf(text: str) -> dict:
    parsed = {}
    for raw_line in (text or "").splitlines():
        line = str(raw_line or "").strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in ZABBIX_DB_KEYS:
            continue
        value = value.strip()
        if not value:
            continue
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        parsed[key] = value
    return parsed


def _quote(value) -> str:
    return shlex.quote(str(value or ""))


def _build_dump_base(db_type: str, db_name: str, db_user: str, db_password: str, exclude_tables: list[str]) -> str:
    if db_type == "postgres":
        exclude_flags = " ".join([f"--exclude-table={_quote(t)}" for t in exclude_tables])
        return (
            f"PGPASSWORD={_quote(db_password)} "
            f"pg_dump -h localhost -U {_quote(db_user)} {exclude_flags} {_quote(db_name)}"
        ).strip()

    exclude_flags = " ".join([f"--ignore-table={_quote(f'{db_name}.{t}')}" for t in exclude_tables])
    return (
        f"MYSQL_PWD={_quote(db_password)} "
        f"mysqldump --single-transaction -h localhost -u {_quote(db_user)} "
        f"{_quote(db_name)} {exclude_flags}"
    ).strip()


def _build_dump_command(dump_base: str, remote_filepath: str) -> tuple[str, str]:
    err_path = f"{remote_filepath}.err"
    remote_q = _quote(remote_filepath)
    err_q = _quote(err_path)
    script = (
        f"rm -f {remote_q} {err_q}; "
        f"{dump_base} 2>{err_q} | gzip > {remote_q}; "
        "dump_status=${PIPESTATUS[0]:-1}; "
        "gzip_status=${PIPESTATUS[1]:-1}; "
        f"size=$(wc -c < {remote_q} 2>/dev/null || echo 0); "
        'echo "__BC_DUMP_STATUS__ dump=${dump_status} gzip=${gzip_status} size=${size:-0}"; '
        f'if [ "${{dump_status}}" -ne 0 ] || [ "${{gzip_status}}" -ne 0 ] || [ "${{size:-0}}" -lt {MIN_REMOTE_DUMP_SIZE} ]; then '
        'echo "__BC_DUMP_ERROR__"; '
        f"cat {err_q} 2>/dev/null; "
        "fi"
    )
    return f"bash -lc {_quote(script)}", err_path


def _parse_dump_result(output: str) -> dict:
    text = str(output or "")
    match = DUMP_STATUS_RE.search(text)
    result = {
        "dump_status": None,
        "gzip_status": None,
        "size": 0,
        "error": "",
    }
    if match:
        result["dump_status"] = int(match.group(1))
        result["gzip_status"] = int(match.group(2))
        result["size"] = int(match.group(3))

    if "__BC_DUMP_ERROR__" in text:
        result["error"] = text.split("__BC_DUMP_ERROR__", 1)[1].strip()
    return result


def _friendly_dump_error(raw_error: str, db_type: str, size: int = 0) -> tuple[str, str]:
    text = re.sub(r"\s+", " ", str(raw_error or "")).strip()
    text = re.sub(r"(?i)\b(PGPASSWORD|MYSQL_PWD)=('([^']*)'|\S+)", r"\1=***", text)
    text = re.sub(r"(?i)(--password=|-p)'?[^'\s]+", r"\1***", text)
    low = text.lower()
    db_label = "PostgreSQL" if db_type == "postgres" else "MariaDB/MySQL"
    client = "pg_dump" if db_type == "postgres" else "mysqldump"

    if "command not found" in low or f"{client}: not found" in low or "no such file" in low:
        return (
            "CONFIGURACAO",
            f"Cliente {db_label} nao encontrado no servidor ({client}). Confira o tipo de banco selecionado ou instale o cliente de dump.",
        )
    if "access denied" in low or "authentication failed" in low or "password authentication failed" in low:
        return (
            "AUTENTICACAO",
            f"Credenciais do banco {db_label} foram recusadas. Confira usuario e senha do banco no cadastro ou no zabbix_server.conf.",
        )
    if "database" in low and ("does not exist" in low or "unknown database" in low):
        return (
            "CONFIGURACAO",
            "Banco de dados informado nao existe no servidor. Confira o nome do banco do Zabbix.",
        )
    if "could not connect" in low or "connection refused" in low or "can't connect" in low or "cannot connect" in low:
        return (
            "CONEXAO",
            f"Nao foi possivel conectar ao banco {db_label} local no servidor Zabbix.",
        )
    if "permission denied" in low:
        return (
            "AUTENTICACAO",
            "Usuario conectado nao tem permissao suficiente para gerar ou gravar o dump temporario.",
        )
    if size and size < MIN_REMOTE_DUMP_SIZE:
        return (
            "CONFIGURACAO",
            "Dump gerado ficou vazio ou pequeno demais. Confira se o tipo de banco selecionado esta correto e se as credenciais acessam o banco do Zabbix.",
        )
    if text:
        return ("SCRIPT", text[:500])
    return (
        "SCRIPT",
        "Comando de dump nao retornou uma confirmacao valida. Confira o tipo de banco e as credenciais cadastradas.",
    )


def _discover_zabbix_db_params(net_connect, logger) -> dict:
    logger.emit(
        f"Tentando descobrir credenciais no arquivo {ZABBIX_DB_CONF_PATH}...",
        "info",
    )
    output = net_connect.send_command_timing(
        f"grep -E '^(DB(Name|User|Password))=' {ZABBIX_DB_CONF_PATH} 2>/dev/null",
        read_timeout=20,
        strip_command=False,
        strip_prompt=False,
    )
    discovered = _parse_zabbix_conf(output)
    if discovered:
        discovered_keys = ", ".join(sorted(discovered.keys()))
        logger.emit(
            f"Parametros detectados em {ZABBIX_DB_CONF_PATH}: {discovered_keys}.",
            "success",
        )
    else:
        logger.emit(
            (
                f"Nenhum parametro DB detectado em {ZABBIX_DB_CONF_PATH}. "
                "Siga com configuracao manual."
            ),
            "warning",
        )
    return discovered


def realizar_backup(
    ip: str,
    usuario: str,
    porta: int,
    nome_provedor: str,
    nome_tipo_equip: str,
    nome_dispositivo: str,
    parametros: dict = None,
    task_id: str = None,
    backup_base_path: str = None,
    **kwargs,
) -> Tuple:
    logger = BackupLogger(nome_dispositivo, task_id)
    logger.emit("Iniciando backup do banco de dados Zabbix...")

    parametros = parametros or {}
    req_params = ["password", "db_type"]
    if not all(k in parametros and parametros[k] for k in req_params):
        msg = f"Falha: Parametros obrigatorios ausentes. Necessario: {', '.join(req_params)}."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    login_password = parametros["password"]
    root_password = parametros.get("root_password")
    enable_password = parametros.get("enable_password")

    device_config = {
        "device_type": "linux",
        "host": ip,
        "port": int(porta),
        "username": usuario,
        "password": login_password,
        "conn_timeout": 35,
        "banner_timeout": 35,
        "auth_timeout": 35,
        "fast_cli": False,
    }

    logger.emit("Etapa 1/4: Testando conexao SSH inicial...")
    try:
        with ConnectHandler(**device_config) as test_connect:
            if not test_connect.is_alive():
                raise RuntimeError("A conexao SSH inicial falhou.")
        logger.emit("Teste de conexao SSH bem-sucedido.", "success")
    except Exception as e:
        msg = friendly_failure_message("AUTENTICACAO", str(e))
        logger.emit(msg, "error")
        return (False, msg, None, "AUTENTICACAO")

    db_mode = str(parametros.get("db_credentials_mode", "manual") or "manual").strip().lower()
    automatic_mode = db_mode == "automatic"
    db_type = _normalize_db_type(parametros.get("db_type", ""))
    db_name = str(parametros.get("db_name", "") or "").strip()
    db_user = str(parametros.get("db_user", "") or "").strip()
    db_password = str(parametros.get("db_password", "") or "").strip()
    exclude_tables = [t.strip() for t in parametros.get("exclude_tables", "").split(",") if t.strip()]
    if automatic_mode:
        logger.emit("Modo de credenciais DB: AUTOMATICO (autodeteccao em tempo de backup).", "info")
    else:
        logger.emit("Modo de credenciais DB: MANUAL.", "info")
    if db_type not in {"postgres", "mariadb"}:
        msg = "Falha: tipo de banco invalido. Selecione PostgreSQL ou MariaDB."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    needs_discovery = automatic_mode or (not all([db_name, db_user, db_password]))
    if needs_discovery:
        if automatic_mode:
            logger.emit(
                "Buscando DBName/DBUser/DBPassword automaticamente via zabbix_server.conf...",
                "info",
            )
        else:
            logger.emit(
                (
                    "Parametros de banco incompletos (db_name/db_user/db_password). "
                    "Tentando preenchimento automatico via zabbix_server.conf..."
                ),
                "warning",
            )
        try:
            with ConnectHandler(**device_config) as net_connect:
                _become_root(net_connect, [root_password, enable_password, login_password, usuario], logger)
                discovered = _discover_zabbix_db_params(net_connect, logger)
                if automatic_mode:
                    db_name = str(discovered.get("DBName", "") or "").strip()
                    db_user = str(discovered.get("DBUser", "") or "").strip()
                    db_password = str(discovered.get("DBPassword", "") or "").strip()
                else:
                    if not db_name:
                        db_name = str(discovered.get("DBName", "") or "").strip()
                    if not db_user:
                        db_user = str(discovered.get("DBUser", "") or "").strip()
                    if not db_password:
                        db_password = str(discovered.get("DBPassword", "") or "").strip()
        except Exception as e:
            if automatic_mode:
                msg = f"Falha no modo automatico ao ler zabbix_server.conf: {e}"
                logger.emit(msg, "error")
                return (False, msg, None, "CONFIGURACAO")
            logger.emit(
                f"Aviso: Falha na descoberta automatica de parametros DB: {e}",
                "warning",
            )

    if not all([db_name, db_user, db_password]):
        msg = (
            "Falha: Parametros de banco ausentes (db_name, db_user, db_password). "
            f"Preencha manualmente ou garanta os campos em {ZABBIX_DB_CONF_PATH}."
        )
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    remote_filepath = f"/tmp/backup_{os.urandom(8).hex()}.sql.gz"
    dump_base = _build_dump_base(db_type, db_name, db_user, db_password, exclude_tables)
    dump_command, remote_error_path = _build_dump_command(dump_base, remote_filepath)

    secrets = [root_password, enable_password, login_password, usuario]

    try:
        logger.emit("Etapa 2/4: Executando dump remoto...")
        with ConnectHandler(**device_config) as net_connect:
            _become_root(net_connect, secrets, logger)
            output = net_connect.send_command_timing(
                dump_command,
                read_timeout=3600,
                strip_command=False,
                strip_prompt=False,
            )
            dump_result = _parse_dump_result(output)
            dump_failed = (
                dump_result["dump_status"] not in (0,)
                or dump_result["gzip_status"] not in (0,)
                or dump_result["size"] < MIN_REMOTE_DUMP_SIZE
            )
            if dump_failed:
                category, detail = _friendly_dump_error(
                    dump_result["error"] or output,
                    db_type,
                    dump_result["size"],
                )
                msg = friendly_failure_message(category, detail, operation="criacao do dump do Zabbix")
                logger.emit(msg, "error")
                return (False, msg, None, category)

        logger.emit(f"Dump remoto concluido com sucesso ({dump_result['size']} bytes).", "success")
    except Exception as e:
        msg = friendly_failure_message("SCRIPT", str(e), operation="criacao do dump do Zabbix")
        logger.emit(msg, "error")
        return (False, msg, None, "SCRIPT")

    local_filepath = prepare_backup_path(
        backup_base_path,
        nome_provedor,
        nome_tipo_equip,
        nome_dispositivo,
        "sql.gz",
    )

    try:
        logger.emit("Etapa 3/4: Iniciando transferencia SFTP...")
        with paramiko.SSHClient() as ssh_client:
            configure_paramiko_host_key_policy(ssh_client)
            ssh_client.connect(
                hostname=ip,
                port=int(porta),
                username=usuario,
                password=login_password,
                timeout=35,
                banner_timeout=35,
                auth_timeout=35,
                look_for_keys=False,
                allow_agent=False,
            )
            with ssh_client.open_sftp() as sftp_client:
                sftp_client.get(remote_filepath, local_filepath)

        local_size = os.path.getsize(local_filepath) if os.path.exists(local_filepath) else 0
        if local_size < MIN_REMOTE_DUMP_SIZE:
            raise RuntimeError(
                "Arquivo baixado esta vazio ou pequeno demais. O dump remoto provavelmente falhou antes da transferencia."
            )
        logger.emit("Transferencia concluida.", "success")
    except Exception as e:
        msg = friendly_failure_message("SCRIPT", str(e), operation="transferencia do dump do Zabbix")
        logger.emit(msg, "error")
        return (False, msg, None, "SCRIPT")

    try:
        logger.emit("Etapa 4/4: Limpando arquivo temporario remoto...")
        with ConnectHandler(**device_config) as net_connect:
            _become_root(net_connect, secrets, logger)
            net_connect.send_command_timing(
                f"rm -f {_quote(remote_filepath)} {_quote(remote_error_path)}",
                read_timeout=60,
                strip_command=False,
                strip_prompt=False,
            )
        logger.emit("Limpeza concluida.", "success")
    except Exception as e:
        logger.emit(f"Aviso: Falha ao limpar o arquivo temporario remoto: {e}", "warning")

    return (True, f"Backup do banco de dados '{db_name}' concluido!", local_filepath, "SUCESSO")

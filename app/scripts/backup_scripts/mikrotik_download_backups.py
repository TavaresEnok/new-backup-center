import os
import re
import shlex
import shutil
import subprocess
from typing import Tuple
from script_helpers import (
    BackupLogger,
    close_ssh_client,
    create_ssh_client,
    sanitize_path_component,
    ssh_host_key_option_list,
    ssh_execute,
)

def run_command(command: list[str], logger, timeout=120):
    """Executa um comando nativo sem shell local e loga o resultado."""
    try:
        log_parts = list(command)
        for idx, part in enumerate(log_parts[:-1]):
            if part == "-p" and idx > 0 and log_parts[idx - 1] == "sshpass":
                log_parts[idx + 1] = "********"
        log_command = shlex.join(log_parts)
        logger.emit(f"Executando comando nativo: {log_command}")

        proc = subprocess.run(command, shell=False, check=True, capture_output=True, text=True, timeout=timeout)
        return True, proc.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = f"Comando nativo falhou. Código: {e.returncode}\nStderr: {e.stderr.strip()}"
        logger.emit(error_msg, 'error')
        return False, error_msg
    except Exception as e:
        error_msg = f"Exceção inesperada ao executar comando nativo: {e}"
        logger.emit(error_msg, 'error')
        return False, error_msg


def _parse_backup_files(file_print_output: str) -> list[str]:
    backup_files: list[str] = []
    for line in (file_print_output or "").splitlines():
        text = line.strip()
        if not text or text.startswith("#") or text.lower().startswith("flags:"):
            continue
        parts = text.split()
        if len(parts) < 2:
            continue
        file_name = parts[1].strip()
        if re.search(r"\.(backup|zip|rsc)$", file_name, re.IGNORECASE):
            backup_files.append(file_name)
    # remove duplicatas mantendo ordem
    seen = set()
    ordered = []
    for name in backup_files:
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)
    return ordered


def _download_via_paramiko(
    *,
    ip: str,
    porta: int,
    usuario: str,
    password: str,
    jump_host: dict,
    timeout: int,
    logger: BackupLogger,
    dir_path: str,
    delete_after_download: bool,
) -> Tuple[bool, str, str | None]:
    client = None
    try:
        client = create_ssh_client(
            host=ip,
            port=int(porta),
            username=usuario,
            password=password,
            jump_host=jump_host,
            timeout=timeout,
        )

        logger.emit("Etapa 1/4: Listando ficheiros no dispositivo via SSH...")
        stdout, stderr, exit_code = ssh_execute(client, "/file print", timeout=max(60, timeout))
        if exit_code != 0 and not stdout:
            raise RuntimeError(f"Falha ao listar ficheiros via SSH. stderr={stderr.strip()}")

        logger.emit("Etapa 2/4: Processando a lista de ficheiros...")
        backup_files = _parse_backup_files(stdout)
        if not backup_files:
            msg = "Nenhum ficheiro de backup (.backup, .zip, .rsc) encontrado no dispositivo."
            logger.emit(msg, "success")
            return (True, msg, dir_path)

        logger.emit(
            f"Encontrados {len(backup_files)} ficheiros de backup: {', '.join(backup_files)}",
            "success",
        )

        logger.emit("Etapa 3/4: Iniciando download dos ficheiros via SFTP...")
        downloaded_count = 0
        sftp = client.open_sftp()
        try:
            for file_name in backup_files:
                local_path = os.path.join(dir_path, os.path.basename(file_name))
                logger.emit(f"--> Baixando '{file_name}'...")
                downloaded = False
                for remote_path in (f"/{file_name}", file_name):
                    try:
                        sftp.get(remote_path, local_path)
                        downloaded = True
                        break
                    except Exception:
                        continue
                if downloaded and os.path.exists(local_path):
                    logger.emit(f"'{file_name}' baixado com sucesso.", "success")
                    downloaded_count += 1
                else:
                    logger.emit(f"Falha ao baixar '{file_name}'.", "error")
        finally:
            try:
                sftp.close()
            except Exception:
                pass

        if downloaded_count < len(backup_files):
            logger.emit(
                f"Aviso: {len(backup_files) - downloaded_count} ficheiro(s) não puderam ser baixados.",
                "warning",
            )
        if downloaded_count == 0 and backup_files:
            raise RuntimeError("Nenhum ficheiro pôde ser baixado com sucesso.")

        if delete_after_download:
            logger.emit("Etapa 4/4: Apagando ficheiros do dispositivo após o download...")
            for file_name in backup_files:
                local_path_check = os.path.join(dir_path, os.path.basename(file_name))
                if os.path.exists(local_path_check):
                    logger.emit(f"--> Apagando '{file_name}'...")
                    safe_name = str(file_name).replace('"', '\\"')
                    cmd = f'/file remove [find name="{safe_name}"]'
                    ssh_execute(client, cmd, timeout=max(30, timeout))
        else:
            logger.emit("Etapa 4/4: Ficheiros mantidos no dispositivo conforme configuração.", "info")

        msg = f"{downloaded_count} de {len(backup_files)} ficheiros de backup foram baixados com sucesso."
        logger.emit(msg, "success")
        return (True, msg, dir_path)
    finally:
        if client is not None:
            close_ssh_client(client)


def _download_via_sshpass(
    *,
    ip: str,
    porta: int,
    usuario: str,
    password: str,
    logger: BackupLogger,
    dir_path: str,
    delete_after_download: bool,
) -> Tuple[bool, str, str | None]:
    ssh_opts = ssh_host_key_option_list()
    ssh_base = ["sshpass", "-p", password, "ssh", *ssh_opts, "-p", str(porta), f"{usuario}@{ip}"]

    logger.emit("Etapa 1/4: Listando ficheiros no dispositivo via SSH...")
    list_command = [*ssh_base, "/file print"]
    success, output = run_command(list_command, logger)
    if not success:
        raise RuntimeError("Não foi possível conectar e listar os ficheiros no dispositivo.")

    logger.emit("Etapa 2/4: Processando a lista de ficheiros...")
    backup_files = _parse_backup_files(output)
    if not backup_files:
        msg = "Nenhum ficheiro de backup (.backup, .zip, .rsc) encontrado no dispositivo."
        logger.emit(msg, "success")
        return (True, msg, dir_path)

    logger.emit(f"Encontrados {len(backup_files)} ficheiros de backup: {', '.join(backup_files)}", "success")
    logger.emit("Etapa 3/4: Iniciando download dos ficheiros via SCP...")

    downloaded_count = 0
    for file_name in backup_files:
        remote_path = f"{usuario}@{ip}:/{file_name}"
        local_path = os.path.join(dir_path, os.path.basename(file_name))
        scp_command = [
            "sshpass",
            "-p",
            password,
            "scp",
            *ssh_opts,
            "-P",
            str(porta),
            remote_path,
            local_path,
        ]
        logger.emit(f"--> Baixando '{file_name}'...")
        success_scp, _ = run_command(scp_command, logger)
        if success_scp and os.path.exists(local_path):
            logger.emit(f"'{file_name}' baixado com sucesso.", "success")
            downloaded_count += 1
        else:
            logger.emit(f"Falha ao baixar '{file_name}'.", "error")

    if downloaded_count < len(backup_files):
        logger.emit(f"Aviso: {len(backup_files) - downloaded_count} ficheiro(s) não puderam ser baixados.", "warning")
    if downloaded_count == 0 and backup_files:
        raise RuntimeError("Nenhum ficheiro pôde ser baixado com sucesso.")

    if delete_after_download:
        logger.emit("Etapa 4/4: Apagando ficheiros do dispositivo após o download...")
        for file_name in backup_files:
            local_path_check = os.path.join(dir_path, os.path.basename(file_name))
            if os.path.exists(local_path_check):
                safe_name = str(file_name).replace("\\", "\\\\").replace('"', '\\"')
                delete_command = [*ssh_base, f'/file remove [find name="{safe_name}"]']
                logger.emit(f"--> Apagando '{file_name}'...")
                run_command(delete_command, logger)
    else:
        logger.emit("Etapa 4/4: Ficheiros mantidos no dispositivo conforme configuração.", "info")

    msg = f"{downloaded_count} de {len(backup_files)} ficheiros de backup foram baixados com sucesso."
    logger.emit(msg, "success")
    return (True, msg, dir_path)


def realizar_backup(ip: str, usuario: str, porta: int, nome_provedor: str, nome_tipo_equip: str,
                      nome_dispositivo: str, parametros: dict = None, task_id: str = None, 
                      backup_base_path: str = None, **kwargs) -> Tuple:
    
    logger = BackupLogger(f"Downloader-{nome_dispositivo}", task_id)
    logger.emit("Iniciando tarefa de download de backups MikroTik...")

    password = (parametros or {}).get('password')
    delete_after_download = str((parametros or {}).get('delete_after_download', 'false')).lower() == 'true'
    jump_host = kwargs.get("jump_host") or (parametros or {}).get("jump_host")
    timeout = int((parametros or {}).get("ssh_timeout", 45) or 45)

    if not password:
        msg = "Falha: 'password' é um parâmetro obrigatório."
        logger.emit(msg, 'error')
        return (False, msg, None, "CONFIGURACAO")

    if not backup_base_path:
        backup_base_path = os.path.join(os.getcwd(), "storage", "backups")

    dir_path = os.path.join(
        backup_base_path,
        sanitize_path_component(nome_provedor),
        sanitize_path_component(nome_tipo_equip),
        sanitize_path_component(nome_dispositivo)
    )
    os.makedirs(dir_path, exist_ok=True)

    try:
        # Caminho principal: paramiko/sftp (não depende de sshpass no container)
        return _download_via_paramiko(
            ip=ip,
            porta=int(porta),
            usuario=usuario,
            password=password,
            jump_host=jump_host,
            timeout=timeout,
            logger=logger,
            dir_path=dir_path,
            delete_after_download=delete_after_download,
        )
    except Exception as e:
        logger.warning(f"Falha no modo paramiko/sftp ({type(e).__name__}). Tentando fallback com sshpass/scp...")
        if not shutil.which("sshpass"):
            msg = f"Ocorreu um erro inesperado: {e}. Também não há 'sshpass' instalado para fallback."
            logger.emit(msg, 'error')
            return (False, msg, None, "SCRIPT")
        try:
            return _download_via_sshpass(
                ip=ip,
                porta=int(porta),
                usuario=usuario,
                password=password,
                logger=logger,
                dir_path=dir_path,
                delete_after_download=delete_after_download,
            )
        except Exception as fallback_exc:
            msg = f"Ocorreu um erro inesperado: {fallback_exc}"
            logger.emit(msg, 'error')
            return (False, msg, None, "SCRIPT")

# /srv/mikrotik_manager/backup_scripts/huawei_olt_final.py
# Versão final, com correção para compatibilidade de algoritmos SSH.

import re
from typing import Tuple
import pexpect
from script_helpers import BackupLogger, prepare_backup_path

def realizar_backup(ip: str, usuario: str, porta: int, nome_provedor: str, nome_tipo_equip: str,
                    nome_dispositivo: str, parametros: dict = None, task_id: str = None, 
                    socketio_instance=None, backup_base_path: str = None) -> Tuple[bool, str, str]:
    
    logger = BackupLogger(nome_dispositivo, task_id, socketio_instance)
    logger.emit(f"Iniciando backup para Huawei OLT: {nome_dispositivo} ({ip})...")

    parametros = parametros or {}
    password = parametros.get('password')

    if not password:
        msg = "Senha não fornecida."
        logger.emit(msg, 'error')
        return (False, msg, None)

    caminho_local_completo = prepare_backup_path(
        backup_base_path,
        nome_provedor, nome_tipo_equip, nome_dispositivo, 'cfg'
    )

    use_telnet = bool(parametros.get('use_telnet'))
    child = None
    prompt_user = r'>\s*$'
    prompt_priv = r'#\s*$'
    prompt_config = r'\(config\)#\s*$'

    try:
        if use_telnet:
            logger.emit(f"Conectando a {ip}:{porta} via TELNET...")
            command = f"telnet {ip} {porta}"
            child = pexpect.spawn(command, timeout=40, encoding='utf-8')
            child.expect(r'(?i)(Username|login):')
            child.sendline(usuario)
        else: # SSH
            logger.emit(f"Conectando a {ip}:{porta} via SSH...")
            # CORREÇÃO: Adiciona a opção para aceitar o algoritmo antigo ssh-rsa
            command = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o HostKeyAlgorithms=+ssh-rsa {usuario}@{ip} -p {porta}"
            child = pexpect.spawn(command, timeout=40, encoding='utf-tópicos8')
        
        child.expect(r'(?i)password:')
        logger.emit("Enviando senha...")
        child.sendline(password)
        
        child.expect(prompt_user, timeout=20)
        logger.emit("Login bem-sucedido.", 'success')

        child.sendline('enable')
        child.expect(prompt_priv, timeout=20)
        logger.emit("Modo privilegiado ativado.", 'success')
        
        logger.emit("Desativando paginação (scroll)...")
        child.sendline('scroll')
        child.expect(r':', timeout=15)
        child.sendline('\n')
        child.expect(prompt_priv, timeout=15)
        logger.emit("Paginação desativada.", 'success')

        logger.emit("Entrando em modo de configuração...")
        child.sendline('config')
        child.expect(prompt_config, timeout=20)
        logger.emit("Modo de configuração ativado.", 'success')
        
        logger.emit("Ativando modo de saída original...")
        child.sendline('mmi-mode original-output')
        child.expect(prompt_config, timeout=20)
        logger.emit("Modo MMI ativado.", 'success')
        
        logger.emit("Executando 'display current-configuration'...")
        child.sendline('display current-configuration')
        
        child.expect(r'\nreturn\r\n', timeout=300)
        full_config = child.before
        child.expect(prompt_config, timeout=20)
        logger.emit("Configuração recebida.", 'success')

        logger.emit("Restaurando modo MMI padrão...")
        child.sendline('undo mmi-mode original-output')
        child.expect(prompt_config, timeout=20)

        with open(caminho_local_completo, 'w', encoding='utf-8') as f:
            f.write(full_config)
        logger.emit(f"Arquivo de backup salvo.", "success")
        
        msg = f"Backup de '{nome_dispositivo}' concluído com sucesso!"
        logger.emit(msg, 'success')
        return (True, msg, caminho_local_completo)
        
    except Exception as e:
        error_msg = f"Falha crítica no script: {e}"
        logger.emit(error_msg, 'error')
        return (False, error_msg, None)
    finally:
        if child and child.isalive():
            child.close()
            logger.emit("Conexão fechada.")

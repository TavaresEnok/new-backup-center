# /srv/mikrotik_manager/backup_scripts/huawei_olt_universal.py
# Script Mestre para OLTs Huawei usando Pexpect para lidar com SSH/Telnet e comandos interativos.

import re
from typing import Tuple
import pexpect
from script_helpers import BackupLogger, prepare_backup_path

def realizar_backup(ip: str, usuario: str, porta: int, nome_provedor: str, nome_tipo_equip: str,
                    nome_dispositivo: str, parametros: dict = None, task_id: str = None, 
                    socketio_instance=None, backup_base_path: str = None) -> Tuple[bool, str, str]:
    
    logger = BackupLogger(nome_dispositivo, task_id, socketio_instance)
    logger.emit(f"Iniciando backup universal para Huawei OLT: {nome_dispositivo} ({ip})...")

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

    try:
        if use_telnet:
            logger.emit(f"Conectando a {ip}:{porta} via TELNET...")
            command = f"/usr/bin/telnet {ip} {porta}"
            child = pexpect.spawn(command, timeout=40, encoding='utf-8')
            child.expect(r'(?i)(Username|login):')
        else: # SSH
            logger.emit(f"Conectando a {ip}:{porta} via SSH...")
            # Pexpect lida com a troca de chaves SSH
            command = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {usuario}@{ip} -p {porta}"
            child = pexpect.spawn(command, timeout=40, encoding='utf-8')
            child.expect(r'(?i)password:')

        # -- A partir daqui, a lógica é a mesma para ambos os protocolos --
        
        # Envia a senha
        logger.emit("Enviando senha...")
        child.sendline(password)
        
        # Espera o prompt de usuário normal '>'
        child.expect(r'>', timeout=20)
        logger.emit("Login bem-sucedido.", 'success')

        # Passo 1: Entrar no modo 'enable' (sem esperar por senha)
        logger.emit("Entrando em modo privilegiado (enable)...")
        child.sendline('enable')
        child.expect(r'#', timeout=20)
        logger.emit("Modo privilegiado ativado.", 'success')
        
        # Passo 2: Entrar no modo de configuração
        logger.emit("Entrando em modo de configuração (config)...")
        child.sendline('config')
        child.expect(r'\(config\)#', timeout=20)
        logger.emit("Modo de configuração ativado.", 'success')
        
        # Passo 3: Desativar a paginação
        logger.emit("Desativando paginação (scroll)...")
        child.sendline('scroll')
        child.expect(r':', timeout=10)
        child.sendline('\n') # Envia Enter para aceitar o default
        child.expect(r'\(config\)#', timeout=10)
        logger.emit("Paginação desativada.", 'success')
        
        # Passo 4: Obter a configuração
        logger.emit("Executando 'display current-configuration'...")
        child.sendline('display current-configuration')
        child.expect(r':', timeout=10)
        child.sendline('\n') # Envia Enter para obter tudo
        
        # Lê a saída completa até encontrar o prompt de config novamente
        child.expect(r'\(config\)#', timeout=300)
        full_config = child.before
        logger.emit("Configuração recebida com sucesso.")

        with open(caminho_local_completo, 'w', encoding='utf-8') as f:
            f.write(full_config)
        logger.emit(f"Arquivo de backup salvo em: {caminho_local_completo}", "success")
        
        msg = f"Backup de '{nome_dispositivo}' concluído com sucesso!"
        logger.emit(msg, 'success')
        return (True, msg, caminho_local_completo)
        
    except Exception as e:
        error_msg = f"Falha crítica no script universal: {e}"
        logger.emit(error_msg, 'error')
        return (False, error_msg, None)
    finally:
        if child and child.isalive():
            child.close()
            logger.emit("Conexão fechada.")

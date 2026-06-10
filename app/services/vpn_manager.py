import subprocess
import time
from backup_scripts.script_helpers import BackupLogger

def run_script(command_list, logger):
    try:
        # Aumentamos o timeout para dar tempo suficiente para a conexão
        result = subprocess.run(command_list, check=True, capture_output=True, text=True, timeout=120)
        for line in result.stdout.strip().split('\n'):
            logger.emit(line)
        return True
    except subprocess.CalledProcessError as e:
        # Erros do script são enviados para stderr
        error_output = e.stderr.strip() if e.stderr else e.stdout.strip()
        logger.emit(f"Falha ao executar o script de conexão. Erro: {error_output}", "error")
        return False

def get_connection_name(p_id):
    return f"provedor_vpn_{p_id}"

def disconnect_and_delete(p_id, logger):
    conn_name = get_connection_name(p_id)
    logger.emit(f"Tentando desconectar e apagar conexão '{conn_name}'...")
    # Usamos o nmcli diretamente para apagar, o que é seguro
    subprocess.run(["nmcli", "connection", "down", conn_name], capture_output=True)
    time.sleep(1)
    subprocess.run(["nmcli", "connection", "delete", conn_name], capture_output=True)

def connect_l2tp(provedor, logger, main_connection_name):
    # Chama o script shell, passando os parâmetros necessários
    command = [
        "/srv/mikrotik_manager/vpn_connect.sh",
        str(provedor.id),
        provedor.nome,
        provedor.vpn_servidor,
        provedor.vpn_usuario,
        provedor.vpn_senha,
        provedor.vpn_ipsec_secret or "" # Garante que não passamos None
    ]
    return run_script(command, logger)

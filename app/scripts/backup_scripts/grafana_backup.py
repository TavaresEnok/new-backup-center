# /srv/mikrotik_manager/backup_scripts/grafana_backup.py
# VERSÃO FINAL COM TESTE DE CONEXÃO

import os
import json
import requests
import shutil
import tempfile
import time
from typing import Tuple
from script_helpers import BackupLogger, friendly_failure_message, friendly_unexpected_error, sanitize_path_component

def realizar_backup(ip: str, usuario: str, porta: int, nome_provedor: str, nome_tipo_equip: str,
                      nome_dispositivo: str, parametros: dict = None, task_id: str = None,
                      backup_base_path: str = None, **kwargs) -> Tuple[bool, str, str]:

    logger = BackupLogger(nome_dispositivo, task_id)
    logger.emit("Iniciando backup do Grafana...")

    parametros = parametros or {}
    grafana_url = parametros.get('grafana_url')
    api_key = parametros.get('api_key')
    if not grafana_url or not api_key:
        msg = "Falha: 'grafana_url' e 'api_key' são obrigatórios."
        logger.emit(msg, 'error')
        return (False, msg, None, "CONFIGURACAO")

    grafana_url = grafana_url.rstrip('/')
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    # --- PASSO 1: TESTE DE CONEXÃO ---
    logger.emit("Etapa 1/2: Testando conexão com a API...")
    try:
        test_response = requests.get(f"{grafana_url}/api/org", headers=headers, timeout=20)
        test_response.raise_for_status() # Lança erro para status HTTP 4xx/5xx
        logger.emit(f"Teste de conexão bem-sucedido. (Organização: {test_response.json().get('name')})", 'success')
    except Exception as e:
        msg = friendly_failure_message("AUTENTICACAO", str(e))
        logger.emit(msg, 'error')
        return (False, msg, None, "AUTENTICACAO")

    # --- PASSO 2: EXECUÇÃO DO BACKUP ---
    dir_path = os.path.join(
        backup_base_path,
        sanitize_path_component(nome_provedor),
        sanitize_path_component(nome_tipo_equip),
        sanitize_path_component(nome_dispositivo)
    )
    os.makedirs(dir_path, exist_ok=True)
    caminho_zip_base = os.path.join(dir_path, f"backup_grafana_{time.strftime('%Y-%m-%d_%H-%M-%S')}")

    try:
        logger.emit("Etapa 2/2: Obtendo a lista de dashboards...")
        response = requests.get(f"{grafana_url}/api/search?query=", headers=headers, timeout=30)
        response.raise_for_status()
        dashboards = response.json()

        if not dashboards:
            msg = "Nenhuma dashboard encontrada."
            logger.emit(msg, 'success')
            return (True, msg, dir_path) # Retorna o diretório como sucesso

        with tempfile.TemporaryDirectory() as temp_dir:
            logger.emit(f"Encontradas {len(dashboards)} dashboards. Iniciando download...")
            for board in dashboards:
                uid, title = board.get('uid'), board.get('title', 'sem_titulo')
                if not uid: continue

                logger.emit(f"--> Baixando: {title}")
                board_resp = requests.get(f"{grafana_url}/api/dashboards/uid/{uid}", headers=headers, timeout=30)

                if board_resp.status_code == 200:
                    json_filename = f"{sanitize_path_component(title)}.json"
                    with open(os.path.join(temp_dir, json_filename), 'w', encoding='utf-8') as f:
                        json.dump(board_resp.json().get('dashboard', {}), f, indent=4, ensure_ascii=False)
                else:
                    logger.emit(f"Falha ao baixar '{title}'. Status: {board_resp.status_code}", 'warning')

            logger.emit("Compactando dashboards em arquivo .zip...")
            shutil.make_archive(caminho_zip_base, 'zip', temp_dir)
            caminho_completo_zip = f"{caminho_zip_base}.zip"

            if not os.path.exists(caminho_completo_zip):
                raise IOError("Arquivo ZIP não foi criado.")

            msg = f"Backup de {len(dashboards)} dashboards concluído!"
            logger.emit(msg, 'success')
            return (True, msg, caminho_completo_zip)

    except Exception as e:
        msg = friendly_unexpected_error(e)
        logger.emit(msg, 'error')
        return (False, msg, None, "SCRIPT")

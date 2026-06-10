from typing import Tuple

from script_helpers import run_basic_netmiko_backup


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
    return run_basic_netmiko_backup(
        ip=ip,
        usuario=usuario,
        porta=porta,
        nome_provedor=nome_provedor,
        nome_tipo_equip=nome_tipo_equip,
        nome_dispositivo=nome_dispositivo,
        parametros=parametros,
        task_id=task_id,
        backup_base_path=backup_base_path,
        device_type='cisco_ios',
        collect_command='show running-config',
        file_extension='txt',
    )

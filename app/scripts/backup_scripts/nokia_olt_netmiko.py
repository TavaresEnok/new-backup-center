from typing import Tuple

from generic_netmiko_profiles import run_profile_backup


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
    return run_profile_backup(
        profile='olt_generic',
        ip=ip,
        usuario=usuario,
        porta=porta,
        nome_provedor=nome_provedor,
        nome_tipo_equip=nome_tipo_equip,
        nome_dispositivo=nome_dispositivo,
        parametros=parametros,
        task_id=task_id,
        backup_base_path=backup_base_path,
        **kwargs,
    )

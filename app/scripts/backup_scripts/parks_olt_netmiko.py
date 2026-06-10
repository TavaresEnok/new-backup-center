from typing import Tuple

from olt_cli_backup import DEFAULT_PAGING_COMMANDS, OltCliProfile, run_olt_cli_backup


PARKS_PROFILE = OltCliProfile(
    vendor_name="OLT Parks",
    paging_commands=DEFAULT_PAGING_COMMANDS,
    backup_commands=(
        "show running-config",
        "show startup-config",
        "show configuration",
        "show running",
        "show startup",
        "display current-configuration",
    ),
    config_markers=(
        "hostname ",
        "interface ",
        "vlan ",
        "ip address",
        "ip route",
        "gpon",
        "epon",
        "pon ",
        "onu ",
        "ont ",
        "service-port",
        "profile ",
        "traffic-profile",
        "snmp-server",
        "end",
    ),
)


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
    return run_olt_cli_backup(
        profile=PARKS_PROFILE,
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

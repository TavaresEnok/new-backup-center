from typing import Tuple

from olt_cli_backup import OltCliProfile, run_olt_cli_backup


TPLINK_PROFILE = OltCliProfile(
    vendor_name="OLT TPLink",
    paging_commands=(
        "terminal length 0",
        "terminal datadump",
        "no page",
        "screen-length disable",
        "screen-length 0",
    ),
    backup_commands=(
        "show running-config",
        "show startup-config",
        "show current-config",
        "show configuration",
        "show config",
        "show running",
        "display current-configuration",
    ),
    config_markers=(
        "hostname ",
        "interface ",
        "vlan ",
        "ip address",
        "gpon",
        "epon",
        "pon ",
        "onu ",
        "ont ",
        "service-port",
        "line-profile",
        "traffic-profile",
        "profile ",
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
        profile=TPLINK_PROFILE,
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

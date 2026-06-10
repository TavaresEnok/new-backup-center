from netmiko import ConnectHandler
from app.models.device import Device
from app.core.security import decrypt_password
from app.scripts.backup_scripts.script_helpers import ssh_strict_host_key_checking_enabled
import os
import datetime

class BackupService:
    @staticmethod
    def get_netmiko_device_type(device_type: str) -> str:
        mapping = {
            'mikrotik': 'mikrotik_routeros',
            'huawei': 'huawei',
            'cisco': 'cisco_ios',
            'ubiquiti': 'ubiquiti_edgerouter',
            'generic': 'generic_termserver'
        }
        return mapping.get(device_type, 'generic_termserver')

    @staticmethod
    def get_backup_command(device_type: str) -> str:
        commands = {
            'mikrotik': '/export',
            'huawei': 'display current-configuration',
            'cisco': 'show running-config',
            'ubiquiti': 'show configuration',
            'generic': 'show configuration'
        }
        return commands.get(device_type, 'show running-config')

    @staticmethod
    def execute_backup(device: Device) -> str:
        """Connects to device and returns configuration string."""
        password = decrypt_password(device.password_encrypted)
        
        device_params = {
            'device_type': BackupService.get_netmiko_device_type(device.device_type),
            'host': device.ip_address,
            'username': device.username,
            'password': password,
            'port': device.port,
            'timeout': 30,
        }
        if ssh_strict_host_key_checking_enabled():
            device_params["ssh_strict"] = True
            device_params["system_host_keys"] = True

        with ConnectHandler(**device_params) as net_connect:
            command = BackupService.get_backup_command(device.device_type)
            config = net_connect.send_command(command)
            return config

    @staticmethod
    def save_backup_file(tenant_id: str, device_id: str, config: str) -> str:
        """Saves config to disk and returns file path."""
        base_dir = f"storage/backups/{tenant_id}/{device_id}"
        os.makedirs(base_dir, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"backup_{timestamp}.cfg"
        file_path = os.path.join(base_dir, filename)
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(config)
            
        return file_path

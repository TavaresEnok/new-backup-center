import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy.orm import Session
from app.models.device import Device
from app.core.database import SessionLocal
from datetime import datetime

class MonitorService:
    """Serviço de monitoramento de conectividade para dispositivos."""
    
    @staticmethod
    def ping_device(ip_address: str) -> bool:
        """Executa um ping no IP fornecido."""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        # Timeout de 1 segundo (1000ms no Windows, -W 1 no Linux)
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        timeout_val = '1000' if platform.system().lower() == 'windows' else '1'
        
        command = ['ping', param, '1', timeout_param, timeout_val, ip_address]
        
        try:
            # shell=True no windows pode ajudar em alguns ambientes, mas lista é mais seguro
            # stdout/stderr para DEVNULL para não poluir o console
            result = subprocess.run(
                command, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                timeout=2 # Timeout de segurança do subprocesso
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def check_all_tenant_devices(db: Session, tenant_id):
        """Verifica o status de todos os dispositivos de um tenant."""
        devices = db.query(Device).filter(Device.tenant_id == tenant_id, Device.is_active == True).all()
        
        results = {'online': 0, 'offline': 0}
        if not devices:
            return results

        # Paraleliza pings para evitar ciclos muito longos em tenants grandes.
        workers = min(64, max(8, len(devices)))
        status_by_device_id = {}

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_device = {
                executor.submit(MonitorService.ping_device, device.ip_address): device
                for device in devices
            }
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    is_online = bool(future.result())
                except Exception:
                    is_online = False
                status_by_device_id[device.id] = 'online' if is_online else 'offline'

        for device in devices:
            new_status = status_by_device_id.get(device.id, 'offline')
            if device.last_connection_status != new_status:
                device.last_connection_status = new_status
            results['online' if new_status == 'online' else 'offline'] += 1
        
        db.commit()
        return results

    @staticmethod
    def update_device_status(device_id: str):
        """Atualiza o status de um único dispositivo."""
        db = SessionLocal()
        try:
            device = db.query(Device).filter_by(id=device_id).first()
            if device:
                is_online = MonitorService.ping_device(device.ip_address)
                device.last_connection_status = 'online' if is_online else 'offline'
                db.commit()
                return device.last_connection_status
        finally:
            db.close()
        return 'unknown'

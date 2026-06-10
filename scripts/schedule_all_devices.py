import sys
import os

# Adds project directory to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.database import SessionLocal
from app.models.device import Device
from app.models.schedule import Schedule, ScheduleFrequency

def schedule_all_devices():
    db = SessionLocal()
    
    # Busca todos os devices do sistema
    devices = db.query(Device).all()
    
    count_created = 0
    count_skipped = 0
    
    print(f"Buscando {len(devices)} dispositivos para agendamento diário automático...")
    
    for device in devices:
        # Verifica se já tem um agendamento
        existing = db.query(Schedule).filter(Schedule.device_id == device.id).first()
        
        if existing:
            # Caso já exista, vamos pular (ou você poderia alterar para forçar daily)
            print(f"[{device.ip_address}] {device.name} já possui agendamento. Ignorando.")
            count_skipped += 1
            continue
            
        # Cria um agendamento novo
        new_schedule = Schedule(
            device_id=device.id,
            frequency=ScheduleFrequency.DAILY,
            time="02:00",  # Horário padrão de backup: 2 da manhã
            is_active=True
        )
        db.add(new_schedule)
        count_created += 1
        print(f"[{device.ip_address}] {device.name} -> Agendamento Diário (02:00) CRIADO.")
        
    db.commit()
    db.close()
    
    print("\n--- RESUMO ---")
    print(f"Agendamentos Criados: {count_created}")
    print(f"Dispositivos Ignorados: {count_skipped}")

if __name__ == '__main__':
    schedule_all_devices()

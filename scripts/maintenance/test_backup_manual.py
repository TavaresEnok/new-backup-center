#!/usr/bin/env python3
"""
Executa backup manual nos 17 dispositivos problemáticos e salva log detalhado
para diagnóstico real do que está acontecendo no script.
"""
import os, sys, json, logging
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

import dotenv; dotenv.load_dotenv(os.path.join(ROOT, ".env"), override=False)
db_url = os.environ.get("DATABASE_URL", "")
if "@db:" in db_url:
    os.environ["DATABASE_URL"] = db_url.replace("@db:", "@172.18.0.3:")

# Logging detalhado para stdout
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
# Silencia libs ruidosas
for noisy in ("paramiko", "urllib3", "asyncio"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

from app.core.database import SessionLocal
from app.models.device import Device
from app.models.tenant import Tenant

# IDs dos 17 dispositivos — Huawei (4), ZTE (3), FiberHome (9), CONECT FIBRA (1 especial)
DEVICE_IDS = {
    # --- Huawei OLT (falso negativo — config descartada) ---
    "76a40994-9321-4128-b0ae-dadd246d2f07": "CAVALCANTINET - OLT HW MA5600 - OLINDA",
    "8aae5e46-8c5d-4cdc-b26d-0a6612ab947f": "GRUPO FLASH PB - OLT HW - RIO TINTO",
    "c5dd54b3-2e79-458f-8232-c76f877ebdfc": "MGN FIBRA - OLT HW X17 (a)",
    "f2ae9667-be4e-4c05-b5d3-85c84c52eb67": "MGN FIBRA - OLT HW X17 (b)",
    # --- ZTE OLT (linhas %Error descartavam tudo) ---
    "5b22ac86-bb5e-4273-9ca0-bfdad6e7ebcb": "OLT ZTE IGARASSU",
    "46b2290d-531b-4c0d-984c-c8f9e367e99c": "OLT ZTE PAU AMARELO",
    "073a625e-eff3-4078-a75e-e7c1fa88d224": "VIBE TELECOM - OLT ZTE CAMPINA GRANDE",
    # --- FiberHome OLT (prompt > ao final do dump) ---
    "eb0d320e-2437-4917-929f-aef7952a7650": "CYBERNET - OLT FIBERHOME - ACUDE",
    "52fc24a5-aa2e-4404-96e6-9d972b7c3b19": "CYBERNET - OLT FIBERHOME - CENTRAL",
    "0d44b3a7-cee7-476f-9f7b-f1fa597f65dc": "G5 CABO - OLT FH",
    "c7271089-f5be-40f0-a110-775258e71eee": "INET - OLT FH - 01",
    "9eab5dfa-fa6c-48db-b646-138a14f4eb3f": "INET - OLT FH - CAIC",
    "0bed14cd-b29f-4203-bc96-ca82612bd424": "MUNDONET - OLT FIBERHOME - RECIFE",
    "7042d28e-4fce-4130-a472-95987c17cebf": "SUCUPIRANET - OLT FIBERHOME",
    "a790e386-5ef1-4826-b6e1-beb6ece7331a": "ULTRANET - OLT FIBERHOME - RAPOSA",
    # --- CONECT FIBRA (caso especial — coletou 183k mas script errou) ---
    "710ffb82-d514-44a8-a3f3-58656eef12f9": "CONECT FIBRA - OLT HW 5800 X2 - CAETES 02",
}

def run_backup(device_id: str, label: str, db):
    from app.services.backup_executor import backup_executor
    from app.models.device_group import DeviceGroup
    from app.models.device_type import DeviceType

    device = db.query(Device).filter_by(id=device_id).first()
    if not device:
        return {"status": "DEVICE_NOT_FOUND", "device_id": device_id}

    group = db.query(DeviceGroup).filter_by(id=device.group_id).first() if device.group_id else None
    dtype = db.query(DeviceType).filter_by(id=device.device_type_id).first() if device.device_type_id else None

    print(f"\n{'='*70}")
    print(f"TESTANDO: {label}")
    print(f"  IP: {device.ip_address}:{device.port}")
    print(f"  Tipo: {dtype.name if dtype else 'N/A'} | Script: {dtype.script_name if dtype else 'N/A'}")
    print(f"  Grupo: {group.name if group else 'N/A'}")
    print(f"{'='*70}")

    t0 = datetime.now()
    try:
        success, message = backup_executor.run_backup_for_device_id(
            device_id=str(device.id),
            manage_vpn=False,  # testa o script diretamente, sem VPN
        )
        duration = (datetime.now() - t0).total_seconds()
        status = "SUCCESS" if success else "FAILED"
        print(f"\n>>> RESULTADO: {status} ({duration:.1f}s)")
        print(f">>> Mensagem: {message}")
        return {
            "device_id": device_id,
            "label": label,
            "status": status,
            "duration_s": round(duration, 1),
            "message": message,
        }
    except Exception as e:
        import traceback
        duration = (datetime.now() - t0).total_seconds()
        print(f"\n>>> EXCEPTION ({duration:.1f}s): {e}")
        traceback.print_exc()
        return {
            "device_id": device_id,
            "label": label,
            "status": "EXCEPTION",
            "duration_s": round(duration, 1),
            "message": str(e),
        }


def main():
    # Filtra por grupo se argumento passado: python test_backup_manual.py huawei
    filter_arg = sys.argv[1].lower() if len(sys.argv) > 1 else "all"

    groups_map = {
        "huawei":    ["CAVALCANTINET", "GRUPO FLASH PB", "MGN FIBRA"],
        "zte":       ["ZTE"],
        "fiberhome": ["FIBERHOME", "OLT FH"],
        "conect":    ["CONECT FIBRA"],
        "all":       [],
    }

    filter_terms = groups_map.get(filter_arg, [])

    db = SessionLocal()
    results = []
    total = 0

    for device_id, label in DEVICE_IDS.items():
        if filter_terms and not any(t.upper() in label.upper() for t in filter_terms):
            continue
        total += 1
        result = run_backup(device_id, label, db)
        results.append(result)

    db.close()

    print(f"\n\n{'='*70}")
    print(f"RESUMO FINAL — {total} dispositivos testados")
    print(f"{'='*70}")
    print(f"{'#':<3} {'Status':<12} {'Dur(s)':<8} {'Dispositivo':<45} Mensagem")
    print("-"*120)
    success_count = 0
    for i, r in enumerate(results, 1):
        st = r["status"]
        if st == "SUCCESS":
            success_count += 1
        print(f"{i:<3} {st:<12} {r['duration_s']:<8} {r['label']:<45} {r['message'][:60]}")

    print(f"\nSucessos: {success_count}/{total}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(ROOT, "reports", "mass_backup_logs", f"teste_manual_{filter_arg}_{ts}.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nJSON salvo: {out_path}")


if __name__ == "__main__":
    main()

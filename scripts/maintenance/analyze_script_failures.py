#!/usr/bin/env python3
"""
Analisa as falhas de backup relacionadas a scripts (não conectividade):
- Authentication timeout
- Falha na coleta do backup
- Outro (mensagens não categorizadas)
- Sem registro de erro
"""
import os
import sys
import csv
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    import dotenv
    dotenv.load_dotenv(os.path.join(ROOT, ".env"), override=False)
except ImportError:
    pass

db_url = os.environ.get("DATABASE_URL", "")
if "@db:" in db_url:
    os.environ["DATABASE_URL"] = db_url.replace("@db:", "@172.18.0.3:")

from app.core.database import SessionLocal
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.tenant import Tenant
from app.services.mass_backup_scope import resolve_mass_backup_excluded_type_ids
from sqlalchemy import or_


def categorize(msg):
    if not msg:
        return "sem_registro"
    if "precheck" in msg or "inalcançável" in msg or "Não foi possível acessar" in msg:
        return "rede"
    if "credenciais foram recusadas" in msg or ("credential" in msg.lower() and "timeout" not in msg.lower()):
        return "credencial"
    if "conectividade" in msg or "encerrada pelo equipamento" in msg:
        return "conectividade"
    if "Authentication timeout" in msg or "authentication timeout" in msg.lower():
        return "auth_timeout"
    if "backup" in msg.lower() and ("falha" in msg.lower() or "fail" in msg.lower() or "curta" in msg.lower() or "vazia" in msg.lower() or "privilegio" in msg.lower()):
        return "falha_coleta"
    if "timeout" in msg.lower():
        return "timeout_generico"
    return "outro"


def main():
    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == "ajust-consulting").first()
        print(f"Tenant: {tenant.name}")

        mass_excluded = resolve_mass_backup_excluded_type_ids(db)
        filt = [
            Device.tenant_id == tenant.id,
            Device.is_active.isnot(False),
            Device.backup_scheduled == True,
        ]
        if mass_excluded:
            filt.append(or_(
                Device.device_type_id.is_(None),
                Device.device_type_id.notin_(list(mass_excluded))
            ))

        failed_devices = (
            db.query(Device)
            .outerjoin(DeviceGroup, Device.group_id == DeviceGroup.id)
            .filter(*filt, Device.last_backup_status == 'failure')
            .order_by(DeviceGroup.name, Device.name)
            .all()
        )

        # Monta lista com categorias de interesse
        script_cats = {"auth_timeout", "falha_coleta", "outro", "sem_registro"}
        records = []

        for device in failed_devices:
            last_b = (
                db.query(Backup)
                .filter(Backup.device_id == device.id, Backup.status == BackupStatus.FAILED)
                .order_by(Backup.created_at.desc())
                .first()
            )
            msg = (last_b.error_message or "") if last_b else ""
            cat = categorize(msg)

            if cat not in script_cats:
                continue

            group_name = device.group.name if device.group else "Sem grupo"
            dtype = device.type.name if device.type else "N/A"

            # Pega também o último backup (qualquer status) p/ ver histórico
            last_any = (
                db.query(Backup)
                .filter(Backup.device_id == device.id)
                .order_by(Backup.created_at.desc())
                .first()
            )

            records.append({
                "categoria": cat,
                "device_id": str(device.id),
                "device_name": device.name,
                "ip_address": device.ip_address,
                "port": device.port,
                "device_type": dtype,
                "group_name": group_name,
                "last_backup_at": device.last_backup_at,
                "backup_id": str(last_b.id) if last_b else "",
                "backup_created_at": last_b.created_at if last_b else None,
                "error_message": msg,
                "last_status_any": last_any.status if last_any else "N/A",
            })

        print(f"\nTotal com falhas de script: {len(records)}")
        by_cat = {}
        for r in records:
            by_cat.setdefault(r["categoria"], []).append(r)
        for cat, rows in sorted(by_cat.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"  {len(rows):3d}  {cat}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # CSV
        csv_path = os.path.join(ROOT, "reports", "mass_backup_logs", f"script_failures_{ts}.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
            writer.writeheader()
            for r in records:
                row = dict(r)
                row["error_message"] = row["error_message"].replace("\n", " | ")
                writer.writerows([row])
        print(f"\nCSV: {csv_path}")

        # Markdown detalhado por categoria
        md_path = os.path.join(ROOT, "reports", "mass_backup_logs", f"script_failures_report_{ts}.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# Análise de Falhas Relacionadas a Scripts de Backup\n\n")
            f.write(f"- **Tenant:** ajust-consulting\n")
            f.write(f"- **Gerado em:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"- **Total analisado:** {len(records)} dispositivos\n\n")
            f.write("---\n\n")

            cat_labels = {
                "auth_timeout": "Authentication Timeout (8)",
                "falha_coleta": "Falha na Coleta do Backup (37)",
                "outro": "Outro — Erro não categorizado (37)",
                "sem_registro": "Sem Registro de Erro (35)",
            }

            for cat, rows in sorted(by_cat.items(), key=lambda x: len(x[1]), reverse=True):
                label = cat_labels.get(cat, cat)
                f.write(f"## {label}\n\n")

                # Agrupa mensagens únicas
                msgs_unique = {}
                for r in rows:
                    m = r["error_message"].strip() or "(vazio)"
                    msgs_unique[m] = msgs_unique.get(m, 0) + 1

                f.write("### Mensagens de erro únicas\n\n")
                for m, cnt in sorted(msgs_unique.items(), key=lambda x: x[1], reverse=True):
                    short = m[:300].replace("\n", " ").replace("|", "/")
                    f.write(f"- **({cnt}x)** `{short}`\n")
                f.write("\n")

                # Tabela de dispositivos
                f.write("### Dispositivos\n\n")
                f.write("| Dispositivo | Tipo | IP | Porta | Grupo | Último Backup | Erro resumido |\n")
                f.write("|-------------|------|----|-------|-------|---------------|---------------|\n")
                for r in rows:
                    err = r["error_message"].replace("\n", " ").replace("|", "/")[:180]
                    ts_str = r["last_backup_at"].strftime("%Y-%m-%d %H:%M") if r["last_backup_at"] else "N/A"
                    f.write(f"| {r['device_name']} | {r['device_type']} | {r['ip_address']} | {r['port']} | {r['group_name']} | {ts_str} | {err} |\n")
                f.write("\n---\n\n")

        print(f"Markdown: {md_path}")

        # Imprime no terminal as mensagens únicas por categoria (para análise imediata)
        print("\n" + "="*70)
        for cat, rows in sorted(by_cat.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"\n### CATEGORIA: {cat.upper()} ({len(rows)} dispositivos)")
            msgs_unique = {}
            for r in rows:
                m = r["error_message"].strip() or "(vazio)"
                msgs_unique[m] = msgs_unique.get(m, 0) + 1
            for m, cnt in sorted(msgs_unique.items(), key=lambda x: x[1], reverse=True):
                short = m[:400].replace("\n", " >> ")
                print(f"  [{cnt}x] {short}")

    finally:
        db.close()


if __name__ == "__main__":
    main()

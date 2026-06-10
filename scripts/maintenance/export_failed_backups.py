#!/usr/bin/env python3
"""
Exporta todos os dispositivos com last_backup_status='failure' do tenant ajust-consulting
usando a mesma lógica do dashboard (dash-grid-5 -> dash-metric).
Inclui ID do dispositivo, nome, IP, porta, grupo e log de erro do último backup.
"""
import os
import sys
import csv
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Override DATABASE_URL to use direct IP (postgres inside Docker bridge)
try:
    import dotenv
    dotenv.load_dotenv(os.path.join(ROOT, ".env"), override=False)
except ImportError:
    pass
db_url = os.environ.get("DATABASE_URL", "")
if "@db:" in db_url:
    db_url = db_url.replace("@db:", "@172.18.0.3:")
    os.environ["DATABASE_URL"] = db_url

from app.core.database import SessionLocal
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.device_type import DeviceType
from app.models.tenant import Tenant
from app.services.mass_backup_scope import resolve_mass_backup_excluded_type_ids
from sqlalchemy import func, or_
from sqlalchemy.orm import outerjoin


def main():
    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == "ajust-consulting").first()
        if not tenant:
            print("ERRO: tenant 'ajust-consulting' não encontrado.")
            return

        print(f"Tenant: {tenant.name} (ID: {tenant.id})")

        # Mesma lógica do dashboard
        mass_excluded_type_ids = resolve_mass_backup_excluded_type_ids(db)
        backup_eligible_filter = [
            Device.tenant_id == tenant.id,
            Device.is_active.isnot(False),
            Device.backup_scheduled == True,
        ]
        if mass_excluded_type_ids:
            backup_eligible_filter.append(
                or_(
                    Device.device_type_id.is_(None),
                    Device.device_type_id.notin_(list(mass_excluded_type_ids)),
                )
            )

        # Dispositivos com falha (igual ao dashboard failed_count)
        failed_devices = (
            db.query(Device)
            .outerjoin(DeviceGroup, Device.group_id == DeviceGroup.id)
            .filter(
                *backup_eligible_filter,
                Device.last_backup_status == 'failure',
            )
            .order_by(DeviceGroup.name, Device.name)
            .all()
        )

        print(f"Dispositivos com last_backup_status='failure': {len(failed_devices)}")

        # Para cada dispositivo, pega o último backup falho com a mensagem de erro
        results = []
        for device in failed_devices:
            last_failed = (
                db.query(Backup)
                .filter(
                    Backup.device_id == device.id,
                    Backup.status == BackupStatus.FAILED,
                )
                .order_by(Backup.created_at.desc())
                .first()
            )
            group_name = device.group.name if device.group else "Sem grupo"
            results.append({
                "device_id": str(device.id),
                "device_name": device.name,
                "ip_address": device.ip_address,
                "port": device.port,
                "group_name": group_name,
                "last_backup_at": device.last_backup_at,
                "backup_id": str(last_failed.id) if last_failed else "",
                "backup_created_at": last_failed.created_at if last_failed else None,
                "error_message": (last_failed.error_message or "").replace("\n", " | ") if last_failed else "N/A",
            })

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # --- CSV ---
        csv_path = os.path.join(ROOT, "reports", "mass_backup_logs", f"failed_devices_{ts}.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "device_id", "device_name", "ip_address", "port",
                "group_name", "last_backup_at", "backup_id", "backup_created_at", "error_message"
            ])
            writer.writeheader()
            writer.writerows(results)
        print(f"\nCSV gerado: {csv_path}")

        # --- Markdown ---
        md_path = os.path.join(ROOT, "reports", "mass_backup_logs", f"failed_devices_report_{ts}.md")

        # Agrupa por grupo
        groups = {}
        for r in results:
            g = r["group_name"]
            groups.setdefault(g, []).append(r)

        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# Relatório de Dispositivos com Último Backup em Falha\n\n")
            f.write(f"- **Tenant:** ajust-consulting\n")
            f.write(f"- **Gerado em:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"- **Critério:** `Device.last_backup_status == 'failure'` (mesma lógica do dashboard)\n")
            f.write(f"- **Total de dispositivos com falha:** {len(results)}\n")
            f.write(f"- **Grupos afetados:** {len(groups)}\n\n")
            f.write("---\n\n")

            # Resumo por grupo
            f.write("## Resumo por Grupo\n\n")
            f.write("| Grupo | Dispositivos com Falha |\n")
            f.write("|-------|------------------------|\n")
            for g, rows in sorted(groups.items(), key=lambda x: len(x[1]), reverse=True):
                f.write(f"| {g} | {len(rows)} |\n")
            f.write("\n---\n\n")

            # Categorias de erro
            error_cats = {}
            for r in results:
                msg = r["error_message"] or ""
                if "precheck" in msg or "inalcançável" in msg or "Não foi possível acessar" in msg:
                    cat = "Rede inalcançável (precheck)"
                elif "credenciais foram recusadas" in msg or "credential" in msg.lower():
                    cat = "Credencial recusada"
                elif "Authentication timeout" in msg or "authentication timeout" in msg.lower():
                    cat = "Authentication timeout"
                elif "conectividade" in msg or "encerrada pelo equipamento" in msg:
                    cat = "Falha de conectividade"
                elif "backup" in msg.lower() and ("falha" in msg.lower() or "fail" in msg.lower()):
                    cat = "Falha na coleta do backup"
                elif "timeout" in msg.lower():
                    cat = "Timeout genérico"
                elif msg == "N/A":
                    cat = "Sem registro de erro"
                else:
                    cat = "Outro"
                error_cats[cat] = error_cats.get(cat, 0) + 1

            f.write("## Categorias de Erro\n\n")
            f.write("| Categoria | Qtd |\n")
            f.write("|-----------|-----|\n")
            for cat, count in sorted(error_cats.items(), key=lambda x: x[1], reverse=True):
                f.write(f"| {cat} | {count} |\n")
            f.write("\n---\n\n")

            # Detalhes por grupo
            f.write("## Detalhes por Grupo\n\n")
            for g, rows in sorted(groups.items()):
                f.write(f"### {g} ({len(rows)} dispositivo(s))\n\n")
                f.write("| Device ID | Dispositivo | IP | Porta | Último Backup | Erro |\n")
                f.write("|-----------|-------------|----|-------|---------------|------|\n")
                for r in rows:
                    err = r["error_message"].replace("|", "/")[:200]
                    ts_str = r["last_backup_at"].strftime("%Y-%m-%d %H:%M") if r["last_backup_at"] else "N/A"
                    dev_id_short = r["device_id"][:8] + "..."
                    f.write(f"| `{dev_id_short}` | {r['device_name']} | {r['ip_address']} | {r['port']} | {ts_str} | {err} |\n")
                f.write("\n")

        print(f"Markdown gerado: {md_path}")

        print("\n--- CATEGORIAS DE ERRO ---")
        for cat, count in sorted(error_cats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {count:4d}  {cat}")

    finally:
        db.close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Limpa logs de tempo real/alertas no Redis por janela de retencao.

Uso:
  PYTHONPATH=/app python /app/app/scripts/maintenance/prune_realtime_logs.py --retention-days 90 --dry-run
  PYTHONPATH=/app python /app/app/scripts/maintenance/prune_realtime_logs.py --retention-days 90 --apply
"""

from __future__ import annotations

import argparse

from app.core.config import settings
from app.services.realtime_backup_logs import prune_global_logs


def main() -> int:
    parser = argparse.ArgumentParser(description="Prune dos logs globais de tempo real no Redis.")
    parser.add_argument(
        "--retention-days",
        type=int,
        default=int(getattr(settings, "REALTIME_LOG_RETENTION_DAYS", 90) or 90),
        help="Dias de retencao dos logs de tempo real.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Somente calcula quantos registros seriam removidos.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Executa a remocao.",
    )
    args = parser.parse_args()

    dry_run = not args.apply
    if args.dry_run:
        dry_run = True

    removed = prune_global_logs(retention_days=args.retention_days, dry_run=dry_run)
    mode = "DRY_RUN" if dry_run else "APPLIED"
    print(f"{mode}|retention_days={args.retention_days}|removed_entries={removed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


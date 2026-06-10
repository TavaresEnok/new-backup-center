#!/usr/bin/env python3
"""
Limpa logs de atividade antigos com modo seguro dry-run por padrao.

Uso:
  PYTHONPATH=/app python /app/app/scripts/maintenance/prune_activity_logs.py --retention-days 180 --dry-run
  PYTHONPATH=/app python /app/app/scripts/maintenance/prune_activity_logs.py --retention-days 180 --apply
"""

from __future__ import annotations

import argparse

from app.core.config import settings
from app.core.database import SessionLocal
from app.services.activity_service import ActivityService


def main() -> int:
    parser = argparse.ArgumentParser(description="Prune de activity_logs por janela de retencao.")
    parser.add_argument(
        "--retention-days",
        type=int,
        default=int(settings.DEFAULT_RETENTION_DAYS or 30),
        help="Dias de retencao (remove registros anteriores a esse limite).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Somente calcula quantos registros seriam removidos (padrao).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Executa a remocao de fato.",
    )
    args = parser.parse_args()

    dry_run = not args.apply
    if args.dry_run:
        dry_run = True

    db = SessionLocal()
    try:
        total = ActivityService.prune_old_logs(
            db=db,
            retention_days=args.retention_days,
            dry_run=dry_run,
        )
    finally:
        db.close()

    mode = "DRY_RUN" if dry_run else "APPLIED"
    print(f"{mode}|retention_days={args.retention_days}|affected_logs={total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


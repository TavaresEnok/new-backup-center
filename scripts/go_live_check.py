#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"


def read_env_file(path: Path) -> dict:
    data = {}
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip()
    return data


def check_env(env_data: dict) -> list[tuple[str, bool, str]]:
    checks = []
    required = ["APP_ENV", "SECRET_KEY", "ENCRYPTION_KEY", "DATABASE_URL", "REDIS_URL"]
    for key in required:
        ok = bool(env_data.get(key))
        checks.append((f"env:{key}", ok, "ok" if ok else "ausente"))

    app_env = env_data.get("APP_ENV", "")
    checks.append(("env:APP_ENV=production", app_env == "production", f"valor={app_env or 'vazio'}"))

    secret_key = env_data.get("SECRET_KEY", "")
    checks.append(("env:SECRET_KEY_default", secret_key != "change-me-in-production", "default" if secret_key == "change-me-in-production" else "ok"))
    return checks


def check_compose_services() -> tuple[bool, str]:
    cmd = ["docker", "compose", "ps", "--services", "--status", "running"]
    try:
        result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return False, result.stderr.strip() or "falha ao executar docker compose ps"
        services = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        needed = {"app", "db", "redis", "celery", "celery_beat"}
        running = set(services)
        missing = sorted(needed - running)
        if missing:
            return False, f"servicos nao rodando: {', '.join(missing)}"
        return True, "ok"
    except Exception as exc:
        return False, str(exc)


def check_http(url: str, attempts: int = 5) -> tuple[bool, str]:
    last_error = "unknown"
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                return resp.status == 200, f"status={resp.status} body={body[:120]}"
        except urllib.error.HTTPError as exc:
            last_error = f"status={exc.code}"
        except Exception as exc:
            last_error = str(exc)
        time.sleep(1)
    return False, last_error


def main() -> int:
    env_data = read_env_file(ENV_PATH)
    base_url = os.getenv("GO_LIVE_BASE_URL", "http://127.0.0.1:8050")
    skip_compose = os.getenv("GO_LIVE_SKIP_COMPOSE", "0") == "1"
    checks: list[tuple[str, bool, str]] = []

    checks.extend(check_env(env_data))
    if skip_compose:
        checks.append(("compose:services", True, "skip"))
    else:
        compose_ok, compose_msg = check_compose_services()
        checks.append(("compose:services", compose_ok, compose_msg))

    health_ok, health_msg = check_http(f"{base_url}/healthz")
    ready_ok, ready_msg = check_http(f"{base_url}/readyz")
    checks.append(("http:/healthz", health_ok, health_msg))
    checks.append(("http:/readyz", ready_ok, ready_msg))

    failures = [c for c in checks if not c[1]]
    print(json.dumps(
        {
            "base_url": base_url,
            "total_checks": len(checks),
            "failed": len(failures),
            "checks": [{"name": n, "ok": ok, "details": d} for n, ok, d in checks],
        },
        indent=2,
        ensure_ascii=False,
    ))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

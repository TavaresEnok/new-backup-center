#!/usr/bin/env python3
import argparse
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPTS_DIR = os.path.join(ROOT, "app", "scripts", "backup_scripts")
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from app.core.database import SessionLocal
from app.core.security import decrypt_password
from app.models import Device, DeviceGroup
from app.services.connection_mode import uses_jump_host
from app.scripts.backup_scripts.script_helpers import (
    close_pexpect_session,
    open_pexpect_session,
    ssh_host_key_options,
)
from app.scripts.backup_scripts.olt_cli_backup import _login, _try_enable, _send_collect


def _jump_host_for_group(group):
    if not group or not uses_jump_host(group) or not group.jump_host:
        return None
    jump_password = decrypt_password(group.jump_password_encrypted) if group.jump_password_encrypted else None
    jump_key = decrypt_password(group.jump_key_encrypted) if group.jump_key_encrypted else None
    return {
        "host": group.jump_host,
        "port": group.jump_port or 22,
        "username": group.jump_username,
        "password": jump_password,
        "key": jump_key,
    }


def main():
    parser = argparse.ArgumentParser(description="Probe CLI help for a device without changing configuration.")
    parser.add_argument("device_id")
    parser.add_argument("commands", nargs="+")
    args = parser.parse_args()

    db = SessionLocal()
    child = None
    try:
        device = db.query(Device).filter_by(id=args.device_id).first()
        if not device:
            raise SystemExit("Device not found")
        group = db.query(DeviceGroup).filter_by(id=device.group_id).first() if device.group_id else None
        password = decrypt_password(device.password_encrypted)
        command = (
            f"telnet {device.ip_address} {int(device.port)}"
            if device.use_telnet
            else (
                f"ssh {ssh_host_key_options()} "
                f"{device.username}@{device.ip_address} -p {int(device.port)}"
            )
        )
        child = open_pexpect_session(
            command,
            jump_host=_jump_host_for_group(group),
            timeout=35,
            encoding="utf-8",
            codec_errors="ignore",
            logger=None,
        )
        ok, reason = _login(child, device.username, password, timeout=28)
        if not ok:
            raise SystemExit(f"Login failed: {reason}")
        _try_enable(child, [device.extra_parameters.get("enable_password") if device.extra_parameters else None, password, device.username])

        for probe in args.commands:
            ok, output = _send_collect(child, probe, timeout_seconds=12)
            text = (output or "").strip()
            print(f"\n===== {probe!r} ok={ok} len={len(text)} =====")
            print(text[:2500])
    finally:
        close_pexpect_session(child)
        db.close()


if __name__ == "__main__":
    main()

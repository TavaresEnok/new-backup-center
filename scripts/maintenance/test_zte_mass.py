#!/usr/bin/env python3
"""
Validação massiva de todas as OLTs ZTE.

Para cada dispositivo testa 3 modos de conexão:
  1. CONFIGURADO  — exatamente como o executor de produção faria (jump/vpn/direto)
  2. DIRETO       — sem jump host (conexão direta IP:porta)
  3. DIRETO+TELNET — direto mas forçando use_telnet=True (útil quando porta=23 está mal cadastrada)

Classifica cada resultado em:
  SUCCESS | REDE_PORTA_FECHADA | JUMP_REDE_INTERNA | CREDENCIAL |
  TIMEOUT | SCRIPT_CONFIG_INVALIDA | BUG_VPN_PATH | REDE_RECUSADA | OUTRO
"""
import os, sys, json, uuid, tempfile
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "app", "scripts", "backup_scripts"))

import dotenv; dotenv.load_dotenv(os.path.join(ROOT, ".env"), override=False)
db_url = os.environ.get("DATABASE_URL", "")
if "@db:" in db_url:
    os.environ["DATABASE_URL"] = db_url.replace("@db:", "@172.18.0.3:")

import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
for noisy in ("paramiko", "urllib3", "asyncio", "passlib", "sqlalchemy"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

TMPDIR = tempfile.mkdtemp(prefix="bc_zte_mass_")
ZTE_TYPE_ID = uuid.UUID("29307300-2cb1-4c09-9089-e4522f52b013")


# ──────────────────────────────────────────────────────────
# Classificação de resultado
# ──────────────────────────────────────────────────────────
def classify(success: bool, msg: str) -> str:
    if success:
        return "SUCCESS"
    m = (msg or "").lower()
    if any(x in m for x in ("inalcançável", "precheck", "não foi possível acessar", "port", "tcp_ok=false", "fail-fast")):
        return "REDE_PORTA_FECHADA"
    if any(x in m for x in ("jump host respondeu mas", "não abriu conexao", "__bc_jh_ready__", "destino não abriu")):
        return "JUMP_REDE_INTERNA"
    if any(x in m for x in ("credenciais foram recusadas", "authentication failed", "credenciais recusadas", "authentication (password) failed")):
        return "CREDENCIAL"
    if any(x in m for x in ("connection timed out", "timed out", "tempo esgotado", "timeout")):
        return "TIMEOUT"
    if "permission denied" in m and "/app" in m:
        return "BUG_VPN_PATH"
    if any(x in m for x in ("curta/vazia", "retornou config", "nao retornou", "não retornou", "meaningful", "muito curto")):
        return "SCRIPT_CONFIG_INVALIDA"
    if any(x in m for x in ("worker_timeout", "softtimelimit", "soft_time")):
        return "TIMEOUT_WORKER"
    if any(x in m for x in ("encerrada pelo equipamento", "connection refused", "connection reset")):
        return "REDE_RECUSADA"
    if any(x in m for x in ("falha ao autenticar", "falha ao estabelecer", "jump host")):
        return "JUMP_AUTH_FAIL"
    return "OUTRO"


# ──────────────────────────────────────────────────────────
# Construção dos parâmetros de cada modo
# ──────────────────────────────────────────────────────────
def build_params(device, group, pw: str, mode: str) -> dict:
    """
    Monta o dict 'parametros' e 'jump_host' para cada modo.
    Retorna: (params_dict, jump_host_dict_or_None, description)
    """
    from app.core.security import decrypt_password
    from app.services.connection_mode import get_effective_connection_type

    params = dict(device.extra_parameters or {})
    params["password"] = pw
    if device.use_telnet:
        params["use_telnet"] = True
        params["usar_telnet"] = True

    jh = None

    if mode == "configured":
        conn_type = get_effective_connection_type(group, device=device) if group else "direct"
        desc = f"configurado ({conn_type})"
        if conn_type == "jump_host" and group and group.jump_host:
            jp = decrypt_password(group.jump_password_encrypted) if group.jump_password_encrypted else None
            jk = decrypt_password(group.jump_key_encrypted) if group.jump_key_encrypted else None
            jh = {"host": group.jump_host, "port": group.jump_port or 22,
                  "username": group.jump_username, "password": jp, "key": jk}
        # vpn: não gerenciamos VPN fora do executor — testa como direto mesmo
        if conn_type == "vpn":
            desc = "configurado (vpn→direto)"

    elif mode == "direct":
        desc = "direto (sem jump)"
        jh = None  # ignora jump host

    elif mode == "direct_telnet":
        desc = "direto + telnet forçado"
        params["use_telnet"] = True
        params["usar_telnet"] = True
        jh = None

    return params, jh, desc


# ──────────────────────────────────────────────────────────
# Executa backup em um modo específico
# ──────────────────────────────────────────────────────────
def run_mode(device, group, device_type, pw: str, mode: str) -> dict:
    import zte_olt_netmiko as zte

    params, jh, desc = build_params(device, group, pw, mode)
    t0 = datetime.now()
    try:
        r = zte.realizar_backup(
            ip=device.ip_address,
            usuario=device.username,
            porta=device.port,
            nome_provedor=group.name if group else "test",
            nome_tipo_equip=device_type.name if device_type else "OLT ZTE",
            nome_dispositivo=device.name,
            parametros=params,
            backup_base_path=TMPDIR,
            jump_host=jh,
        )
        duration = (datetime.now() - t0).total_seconds()
        success = bool(r[0])
        msg = str(r[1] or "")
        sz = os.path.getsize(r[2]) if success and r[2] else 0
    except Exception as e:
        duration = (datetime.now() - t0).total_seconds()
        success = False
        msg = str(e)
        sz = 0

    cat = classify(success, msg)
    return {
        "mode": mode, "desc": desc, "success": success,
        "cat": cat, "bytes": sz, "duration": round(duration, 1),
        "msg": msg[:300],
    }


# ──────────────────────────────────────────────────────────
# Lê todos os dados de um dispositivo do banco (sem manter conexão aberta)
# ──────────────────────────────────────────────────────────
def load_device_data(dev_id: str) -> dict | None:
    """Abre DB, lê tudo, fecha DB imediatamente. Retorna dict com dados serializados."""
    from app.core.database import SessionLocal
    from app.models.device import Device
    from app.models.device_group import DeviceGroup
    from app.models.device_type import DeviceType
    from app.core.security import decrypt_password
    from app.services.connection_mode import get_effective_connection_type

    db = SessionLocal()
    try:
        d = db.query(Device).filter(Device.id == uuid.UUID(dev_id)).first()
        if not d:
            return None
        g  = db.query(DeviceGroup).filter_by(id=d.group_id).first() if d.group_id else None
        dt = db.query(DeviceType).filter_by(id=d.device_type_id).first() if d.device_type_id else None

        pw = decrypt_password(d.password_encrypted)
        jp = decrypt_password(g.jump_password_encrypted) if g and g.jump_password_encrypted else None
        jk = decrypt_password(g.jump_key_encrypted) if g and g.jump_key_encrypted else None
        conn_type = get_effective_connection_type(g, device=d) if g else "direct"

        return {
            "id": str(d.id),
            "name": d.name,
            "ip": d.ip_address,
            "port": d.port,
            "username": d.username,
            "password": pw,
            "use_telnet": bool(d.use_telnet),
            "extra_parameters": dict(d.extra_parameters or {}),
            "group_name": g.name if g else "sem grupo",
            "group_type": dt.name if dt else "OLT ZTE",
            "conn_type": conn_type,
            "jump_host": g.jump_host if g and g.jump_host else None,
            "jump_port": g.jump_port or 22 if g else 22,
            "jump_username": g.jump_username if g else None,
            "jump_password": jp,
            "jump_key": jk,
            "prev_status": d.last_backup_status or "never",
        }
    finally:
        db.close()


# ──────────────────────────────────────────────────────────
# Executa backup de um modo — sem nenhum acesso a banco
# ──────────────────────────────────────────────────────────
def run_mode_from_data(data: dict, mode: str) -> dict:
    """Roda o backup usando apenas o dict de dados pré-carregado (sem DB)."""
    import zte_olt_netmiko as zte

    params = dict(data["extra_parameters"])
    params["password"] = data["password"]
    jh = None

    if mode == "configured":
        desc = f"configurado ({data['conn_type']})"
        if data["use_telnet"]:
            params["use_telnet"] = True
            params["usar_telnet"] = True
        if data["conn_type"] == "jump_host" and data["jump_host"]:
            jh = {
                "host": data["jump_host"], "port": data["jump_port"],
                "username": data["jump_username"], "password": data["jump_password"],
                "key": data["jump_key"],
            }

    elif mode == "direct":
        desc = "direto (sem jump/vpn)"
        if data["use_telnet"]:
            params["use_telnet"] = True
            params["usar_telnet"] = True
        jh = None

    elif mode == "direct_telnet":
        desc = "direto + telnet forçado"
        params["use_telnet"] = True
        params["usar_telnet"] = True
        jh = None

    elif mode == "direct_ssh":
        desc = "direto + SSH forçado"
        params["use_telnet"] = False
        params["usar_telnet"] = False
        jh = None

    t0 = datetime.now()
    try:
        r = zte.realizar_backup(
            ip=data["ip"], usuario=data["username"], porta=data["port"],
            nome_provedor=data["group_name"], nome_tipo_equip=data["group_type"],
            nome_dispositivo=data["name"],
            parametros=params, backup_base_path=TMPDIR, jump_host=jh,
        )
        duration = (datetime.now() - t0).total_seconds()
        success = bool(r[0])
        msg = str(r[1] or "")
        sz = os.path.getsize(r[2]) if success and r[2] else 0
    except Exception as e:
        duration = (datetime.now() - t0).total_seconds()
        success = False
        msg = str(e)
        sz = 0

    cat = classify(success, msg)
    return {"mode": mode, "desc": desc, "success": success,
            "cat": cat, "bytes": sz, "duration": round(duration, 1), "msg": msg[:300]}


# ──────────────────────────────────────────────────────────
# Testa um dispositivo nos 3 modos (sem manter DB aberto)
# ──────────────────────────────────────────────────────────
def test_device(dev_id: str, dev_name: str) -> dict:
    data = load_device_data(dev_id)  # DB aberto/fechado aqui, rápido
    if not data:
        return {"name": dev_name, "device_id": dev_id, "error": "NOT_FOUND",
                "diagnosis": "NOT_FOUND", "modes": []}

    info = {
        "name": data["name"], "device_id": dev_id,
        "ip": f"{data['ip']}:{data['port']}",
        "telnet": data["use_telnet"],
        "group": data["group_name"],
        "conn_type_configured": data["conn_type"],
        "jump_host": data["jump_host"],
        "prev_status": data["prev_status"],
        "modes": [],
    }

    # ── Modo 1: conexão configurada no grupo ──
    print(f"     → modo 1/3: {data['conn_type']} (configurado)...", flush=True)
    m1 = run_mode_from_data(data, "configured")
    info["modes"].append(m1)
    print(f"        {'✅' if m1['success'] else '❌'} {m1['cat']} | {m1['bytes']:,}b | {m1['duration']}s | {m1['msg'][:70]}", flush=True)

    # ── Modo 2: direto sem jump/vpn (se configurado != direto ou falhou) ──
    if data["conn_type"] != "direct" or not m1["success"]:
        print(f"     → modo 2/3: direto (sem jump/vpn)...", flush=True)
        m2 = run_mode_from_data(data, "direct")
        info["modes"].append(m2)
        print(f"        {'✅' if m2['success'] else '❌'} {m2['cat']} | {m2['bytes']:,}b | {m2['duration']}s | {m2['msg'][:70]}", flush=True)
    else:
        print(f"     → modo 2/3: pulado (configurado=direto e já teve sucesso)", flush=True)

    # ── Modo 3: telnet↔SSH invertido (só se ainda nenhum sucesso) ──
    any_success = any(m["success"] for m in info["modes"])
    if not any_success:
        mode3 = "direct_ssh" if data["use_telnet"] else "direct_telnet"
        print(f"     → modo 3/3: {mode3}...", flush=True)
        m3 = run_mode_from_data(data, mode3)
        info["modes"].append(m3)
        print(f"        {'✅' if m3['success'] else '❌'} {m3['cat']} | {m3['bytes']:,}b | {m3['duration']}s | {m3['msg'][:70]}", flush=True)
    else:
        print(f"     → modo 3/3: pulado (sucesso obtido)", flush=True)

    # ── Diagnóstico final ──
    any_success = any(m["success"] for m in info["modes"])
    cats = [m["cat"] for m in info["modes"]]
    if any_success:
        winning = next(m for m in info["modes"] if m["success"])
        info["diagnosis"] = f"SUCESSO via {winning['desc']}"
    elif all(c in ("REDE_PORTA_FECHADA", "JUMP_REDE_INTERNA", "REDE_RECUSADA") for c in cats):
        info["diagnosis"] = "REDE — porta/rota indisponível em todos os modos"
    elif all(c in ("TIMEOUT", "REDE_PORTA_FECHADA", "JUMP_REDE_INTERNA", "REDE_RECUSADA") for c in cats):
        info["diagnosis"] = "REDE/TIMEOUT — sem resposta em todos os modos"
    elif any(c == "CREDENCIAL" for c in cats) and all(c in ("CREDENCIAL","TIMEOUT","REDE_PORTA_FECHADA","JUMP_REDE_INTERNA") for c in cats):
        info["diagnosis"] = "CREDENCIAL — senha/usuário inválido"
    elif any(c == "SCRIPT_CONFIG_INVALIDA" for c in cats):
        info["diagnosis"] = "SCRIPT — conectou mas retornou config inválida"
    elif any(c == "BUG_VPN_PATH" for c in cats):
        info["diagnosis"] = "BUG VPN/PATH — executor sem acesso ao /app"
    elif any(c == "JUMP_AUTH_FAIL" for c in cats):
        info["diagnosis"] = "JUMP HOST — credencial do jump host inválida"
    else:
        info["diagnosis"] = f"MISTO — {', '.join(dict.fromkeys(cats))}"

    return info


# ──────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────
def main():
    from app.core.database import SessionLocal
    from app.models.device import Device

    db = SessionLocal()
    devices = (
        db.query(Device)
        .filter(
            Device.device_type_id == ZTE_TYPE_ID,
            Device.is_active.isnot(False),
            Device.backup_scheduled == True,
        )
        .order_by(Device.name)
        .all()
    )
    device_list = [(str(d.id), d.name, d.last_backup_status or "never") for d in devices]
    db.close()

    total = len(device_list)
    print(f"\n{'='*80}")
    print(f"VALIDAÇÃO MASSIVA — OLTs ZTE  ({total} dispositivos)")
    print(f"3 modos por dispositivo: configurado | direto | direto+telnet/ssh")
    print(f"Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*80}\n")

    results = []
    for i, (dev_id, name, prev) in enumerate(device_list, 1):
        print(f"[{i:2d}/{total}] {name}  (status atual: {prev})", flush=True)
        r = test_device(dev_id, name)
        results.append(r)
        diag = r.get("diagnosis", "?")
        print(f"     ▶ DIAGNÓSTICO: {diag}\n", flush=True)

    # ── Sumário final ──
    print(f"\n{'='*80}")
    print(f"SUMÁRIO FINAL")
    print(f"{'='*80}\n")

    diag_groups = {}
    for r in results:
        d = r.get("diagnosis", "?")
        diag_groups.setdefault(d, []).append(r["name"])

    print(f"{'Diagnóstico':<50} Qtd   Dispositivos")
    print("-"*100)
    for diag, names in sorted(diag_groups.items(), key=lambda x: len(x[1]), reverse=True):
        icon = "✅" if "CORRIGIDO" in diag else "❌"
        sample = ", ".join(n[:30] for n in names[:3])
        more = f"... +{len(names)-3}" if len(names) > 3 else ""
        print(f"{icon} {diag:<48} {len(names):>3}   {sample}{more}")

    success_total = sum(1 for r in results if "CORRIGIDO" in r.get("diagnosis",""))
    fail_total = total - success_total
    print(f"\n✅ Funcionaram (ao menos 1 modo): {success_total}")
    print(f"❌ Todos os modos falharam: {fail_total}")

    # ── Tabela detalhada ──
    print(f"\n{'#':<3} {'Nome':<48} {'Conn':<10} {'Mod1':<22} {'Mod2':<22} {'Mod3':<22} Diagnóstico")
    print("-"*170)
    for i, r in enumerate(results, 1):
        modes = r.get("modes", [])
        def mfmt(m):
            if not m: return "-"*21
            icon = "✅" if m["success"] else "❌"
            return f"{icon} {m['cat'][:15]} {m['bytes']//1024:>4}KB"[:21]
        m1 = mfmt(modes[0] if len(modes) > 0 else None)
        m2 = mfmt(modes[1] if len(modes) > 1 else None)
        m3 = mfmt(modes[2] if len(modes) > 2 else None)
        conn = r.get("conn_type_configured","?")[:9]
        print(f"{i:<3} {r['name'][:47]:<48} {conn:<10} {m1:<22} {m2:<22} {m3:<22} {r.get('diagnosis','?')[:40]}")

    # ── Salva JSON ──
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = os.path.join(ROOT, "reports", "mass_backup_logs", f"zte_mass_test_{ts}.json")
    out_md   = os.path.join(ROOT, "reports", "mass_backup_logs", f"zte_mass_test_{ts}.md")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    print(f"\nJSON: {out_json}")

    # ── Markdown ──
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(f"# Validação Massiva OLTs ZTE\n\n")
        f.write(f"- **Data:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"- **Total:** {total} dispositivos\n")
        f.write(f"- **Sucesso (≥1 modo):** {success_total}\n")
        f.write(f"- **Falha total:** {fail_total}\n\n---\n\n")
        f.write("## Sumário por Diagnóstico\n\n")
        f.write("| Diagnóstico | Qtd | Dispositivos |\n|---|---|---|\n")
        for diag, names in sorted(diag_groups.items(), key=lambda x: len(x[1]), reverse=True):
            icon = "✅" if "CORRIGIDO" in diag else "❌"
            f.write(f"| {icon} {diag} | {len(names)} | {', '.join(names[:5])} {'...' if len(names)>5 else ''} |\n")
        f.write("\n---\n\n## Detalhes por Dispositivo\n\n")
        f.write("| # | Dispositivo | IP | Grupo | Conn | Modo 1 (config) | Modo 2 (direto) | Modo 3 | Diagnóstico |\n")
        f.write("|---|---|---|---|---|---|---|---|---|\n")
        for i, r in enumerate(results, 1):
            modes = r.get("modes", [])
            def mmd(m):
                if not m: return "—"
                icon = "✅" if m["success"] else "❌"
                return f"{icon} {m['cat']} ({m['bytes']//1024}KB, {m['duration']}s)"
            f.write(f"| {i} | {r['name']} | {r.get('ip','')} | {r.get('group','')} | {r.get('conn_type_configured','')} | {mmd(modes[0] if modes else None)} | {mmd(modes[1] if len(modes)>1 else None)} | {mmd(modes[2] if len(modes)>2 else None)} | {r.get('diagnosis','')} |\n")

    print(f"Markdown: {out_md}")

if __name__ == "__main__":
    main()

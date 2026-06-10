import re
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple


FAILURE_LABELS = {
    "auth": "Autenticacao",
    "timeout": "Timeout",
    "banner_timeout": "Banner SSH (sobrecarga/lentidao)",
    "jump_session_closed": "Sessao Jump Host encerrada",
    "port_refused": "Porta recusada",
    "vpn": "VPN",
    "vpn_worker": "Worker VPN",
    "config": "Cadastro/configuração",
    "no_ping": "Sem ping",
    "connection": "Conectividade",
    "circuit_breaker": "Jump Host bloqueado (Circuit Breaker)",
    "script": "Script",
    "unknown": "Outros",
}

TRANSIENT_FAILURE_CATEGORIES = {
    "timeout",
    "connection",
    "vpn",
    "jump_session_closed",
}

_ROUTEROS_TIMESTAMP_RE = re.compile(r"^\s*#\s+.+\s+by\s+RouterOS\s+.+$", re.IGNORECASE)
_VOLATILE_LINE_PATTERNS = [
    re.compile(r"^\s*#\s+(jan|fev|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[/\s-]", re.IGNORECASE),
    re.compile(r"^\s*current configuration\s*:.*$", re.IGNORECASE),
    re.compile(r"^\s*building configuration.*$", re.IGNORECASE),
    re.compile(r"^\s*last configuration change.*$", re.IGNORECASE),
    re.compile(r"^\s*ntp clock-period.*$", re.IGNORECASE),
    re.compile(r"^\s*!\s*time:\s*.*$", re.IGNORECASE),
    re.compile(r"^\s*!\s*generated.*$", re.IGNORECASE),
]
_HARD_ERROR_TOKENS = (
    "connection refused",
    "unable to connect",
    "authentication failed",
    "invalid input",
    "unknown command",
    "syntax error",
    "error:",
    "traceback",
)


def classify_failure(message: str) -> str:
    text = (message or "").strip().lower()
    if not text:
        return "unknown"

    # Circuit breaker: bloqueio por saturacao de Jump Host.
    if "circuit breaker" in text and ("aberto" in text or "ativado" in text or "bloqueado" in text):
        return "circuit_breaker"

    # Banner SSH: jump host sobrecarregado — NAO e transitorio (retry piora a saturacao).
    # Deve ser verificado ANTES do 'timeout' generico para ter prioridade.
    if "error reading ssh protocol banner" in text:
        return "banner_timeout"

    # Sessao de jump encerrada antes de abrir shell costuma ser intermitente de transporte
    # (saturacao, race de canal, queda curta de bastion). Mantemos categoria dedicada
    # para tratar retry sem poluir "connection" generico.
    if any(
        marker in text
        for marker in (
            "sessao com jump host encerrada",
            "sessão com jump host encerrada",
            "nao foi possivel abrir shell interativo no jump host",
            "não foi possível abrir shell interativo no jump host",
        )
    ):
        return "jump_session_closed"

    if "jump host respondeu mas o dispositivo destino" in text:
        return "connection"

    # Credencial recusada pelo equipamento (a conexao FUNCIONOU, a autenticacao e que falhou)
    # e sinal forte e inequivoco de AUTENTICACAO. Precisa vir ANTES de timeout/connection
    # porque o detalhe dessas mensagens costuma mencionar conectividade/tempo sem mudar a
    # causa raiz — caso contrario "credenciais recusadas" cai em Conectividade/Timeout.
    if any(
        m in text
        for m in (
            "credenciais foram recusadas",
            "credenciais recusadas",
            "credencial recusada",
            "credenciais invalidas",
            "credenciais inválidas",
        )
    ):
        return "auth"

    # Prioriza falhas de conectividade/timeout antes de "credenciais" em mensagens genéricas.
    # IMPORTANTE: as mensagens chegam aqui JA traduzidas para portugues amigavel por
    # friendly_failure_message()/friendly_unexpected_error() (ex.: "Tempo esgotado aguardando
    # resposta", "Falha de conectividade com o dispositivo"). Por isso os marcadores precisam
    # cobrir tanto os termos tecnicos em ingles quanto o vocabulario PT amigavel — caso
    # contrario falhas obvias caem em "unknown"/"Outros" no relatorio.
    if any(k in text for k in ["timed out", "timeout", "timeoutexception", "softtimelimitexceeded", "tempo esgotado", "tempo limite"]):
        return "timeout"
    if any(
        k in text
        for k in [
            "rede inalcan",
            "não foi possível acessar a porta",
            "nao foi possivel acessar a porta",
            "precheck/fail-fast",
            "falha de conectividade",
            "conectividade com o dispositivo",
            "estabelecer conexao",
            "estabelecer conexão",
            "estabelecer conexao valida",
            "encerrada pelo equipamento",
            "conexao foi encerrada",
            "conexão foi encerrada",
            "rota/acesso de rede",
            "nao ha rota",
            "não há rota",
            "no route to host",
            "kex_exchange",
            "escape character",
        ]
    ):
        return "connection"
    if any(k in text for k in ["connection refused", "refused", "errno 111", "port closed", "porta recusou", "recusou a conex", "a porta recusou"]):
        return "port_refused"
    if any(k in text for k in ["eof", "connection closed", "socket", "network", "host unreachable", "no route to host", "tcp connection", "ssh", "telnet"]):
        return "connection"
    if any(k in text for k in ["sem resposta ao ping", "no ping", "icmp", "100% packet loss"]):
        return "no_ping"
    if any(k in text for k in ["auth", "autentic", "credencia", "senha", "password", "access denied", "permission denied", "login failed", "unauthorized", "invalid credentials", "has been locked", "cannot log on"]):
        return "auth"
    if any(k in text for k in ["worker vpn", "networkmanager indispon", "nmcli não encontrado", "nmcli nao encontrado"]):
        return "vpn_worker"
    if any(k in text for k in ["grafana_url", "api_key", "cadastro incomplet", "cadastro invalid", "cadastro inválid"]):
        return "config"
    if any(k in text for k in ["vpn", "nmcli", "l2tp", "ipsec", "ppp"]):
        return "vpn"
    if any(k in text for k in ["script", "traceback", "syntaxerror", "attributeerror", "typeerror", "keyerror", "modulenotfound", "importerror", "configuracao retornada", "configuração retornada", "retornou configuracao", "retornou configuração", "nao retornou configuracao", "não retornou configuração", "coleta do backup", "integridade do arquivo", "arquivo muito pequeno", "muito curta", "configuracao valida", "configuração válida", "criacao do dump", "criação do dump", "pg_dump", "dump retornou", "dump do zabbix"]):
        return "script"
    return "unknown"


def failure_label(category: str) -> str:
    return FAILURE_LABELS.get((category or "").strip().lower(), FAILURE_LABELS["unknown"])


def is_transient_failure(category: str) -> bool:
    return (category or "").strip().lower() in TRANSIENT_FAILURE_CATEGORIES


def parse_iso_utc(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def is_connection_ready_recent(extra_parameters: Dict[str, Any], max_age_minutes: int = 30, now_utc: Optional[datetime] = None) -> Tuple[bool, str]:
    extra = extra_parameters if isinstance(extra_parameters, dict) else {}
    group = str(extra.get("connection_test_group") or "").strip().lower()
    if group != "ready":
        return False, "sem ping+login OK no ultimo teste"

    last_at = parse_iso_utc(extra.get("connection_test_last_at"))
    if not last_at:
        return False, "sem timestamp do ultimo teste ping/login"

    now = now_utc or datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=max(1, int(max_age_minutes or 30)))
    if last_at < cutoff:
        return False, f"teste ping/login desatualizado (> {int(max_age_minutes or 30)} min)"

    return True, "ready"


def is_connection_ready_for_backup(extra_parameters: Dict[str, Any]) -> Tuple[bool, str]:
    extra = extra_parameters if isinstance(extra_parameters, dict) else {}
    group = str(extra.get("connection_test_group") or "").strip().lower()
    if group != "ready":
        return False, "sem ping+login OK no ultimo teste"

    last_at = parse_iso_utc(extra.get("connection_test_last_at"))
    if not last_at:
        return False, "sem timestamp do ultimo teste ping/login"

    return True, "ready"


def normalize_config_lines(content: str) -> Tuple[list[str], int]:
    text = (content or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    dropped = 0
    normalized = []
    for raw in lines:
        line = raw.rstrip()
        if _ROUTEROS_TIMESTAMP_RE.match(line):
            dropped += 1
            continue
        if any(p.match(line) for p in _VOLATILE_LINE_PATTERNS):
            dropped += 1
            continue
        normalized.append(line)

    # Remove excesso de linhas em branco consecutivas.
    compact = []
    blank_streak = 0
    for line in normalized:
        if not line.strip():
            blank_streak += 1
            if blank_streak > 1:
                dropped += 1
                continue
        else:
            blank_streak = 0
        compact.append(line)
    return compact, dropped


def validate_backup_integrity(file_path: Optional[str], device_type_name: str = "", script_name: str = "") -> Dict[str, Any]:
    result = {
        "ok": False,
        "reason": "",
        "size_bytes": 0,
        "line_count": 0,
        "markers_found": [],
    }
    if not file_path:
        result["reason"] = "arquivo ausente"
        return result

    lower_path = str(file_path).strip().lower()
    if lower_path.endswith(".zip"):
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                infos = [info for info in zf.infolist() if not info.is_dir()]
                if not infos:
                    result["reason"] = "zip sem arquivos de configuracao"
                    return result
                total_size = sum(int(i.file_size or 0) for i in infos)
                result["size_bytes"] = total_size
                result["line_count"] = len(infos)
                if total_size < 128:
                    result["reason"] = "zip muito pequeno (<128 bytes)"
                    return result
                result["ok"] = True
                result["reason"] = "integridade validada (zip)"
                result["markers_found"] = [f"zip_entries={len(infos)}"]
                return result
        except Exception as exc:
            result["reason"] = f"zip invalido: {exc}"
            return result

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as exc:
        result["reason"] = f"nao foi possivel ler arquivo: {exc}"
        return result

    size_bytes = len(content.encode("utf-8", errors="ignore"))
    lines = content.splitlines()
    line_count = len(lines)
    result["size_bytes"] = size_bytes
    result["line_count"] = line_count

    if size_bytes < 128:
        result["reason"] = "arquivo muito pequeno (<128 bytes)"
        return result
    if line_count < 5:
        result["reason"] = "arquivo com poucas linhas (<5)"
        return result

    token = f"{(device_type_name or '').lower()} {(script_name or '').lower()} {(content or '').lower()[:4000]}"
    markers = []

    marker_sets = [
        ("routeros", ["/interface", "/ip", "routeros", "# model ="]),
        ("huawei", ["display current-configuration", "sysname", "interface", "vlan"]),
        ("zte", ["show running-config", "interface", "vlan"]),
        ("fiberhome", ["show running-config", "terminal length 0", "interface"]),
        ("switch", ["interface", "vlan", "hostname"]),
        ("cisco", ["version", "hostname", "interface"]),
        ("datacom", ["show running-config", "interface", "vlan"]),
        ("intelbras", ["show running-config", "interface"]),
        ("parks", ["show running-config", "interface"]),
        ("fortinet", ["config system", "set hostname", "config firewall"]),
        ("juniper", ["set interfaces", "set system host-name", "set protocols"]),
        ("a10", ["show running-config", "slb server", "slb virtual-server"]),
    ]

    expected = []
    if any(k in token for k in ["mikrotik", "routeros"]):
        expected = marker_sets[0][1]
    elif "huawei" in token:
        expected = marker_sets[1][1]
    elif "zte" in token:
        expected = marker_sets[2][1]
    elif "fiberhome" in token:
        expected = marker_sets[3][1]
    elif "datacom" in token:
        expected = marker_sets[6][1]
    elif "intelbras" in token:
        expected = marker_sets[7][1]
    elif "parks" in token:
        expected = marker_sets[8][1]
    elif "fortinet" in token:
        expected = marker_sets[9][1]
    elif "juniper" in token:
        expected = marker_sets[10][1]
    elif "a10" in token:
        expected = marker_sets[11][1]
    elif "switch" in token:
        expected = marker_sets[4][1]
    elif "cisco" in token:
        expected = marker_sets[5][1]

    if expected:
        content_l = content.lower()
        for marker in expected:
            if marker.lower() in content_l:
                markers.append(marker)

    result["markers_found"] = markers
    if expected and len(markers) == 0:
        content_l = content.lower()
        hard_errors = sum(1 for token in _HARD_ERROR_TOKENS if token in content_l)
        # Heuristica para firmwares legados: arquivos grandes e com estrutura de config
        # podem ser validos mesmo sem markers especificos do mapeamento.
        plausible_config = (
            size_bytes >= 512
            and line_count >= 20
            and any(k in content_l for k in ("interface", "vlan", "display", "startup", "running-config", "/ip", "/interface"))
        )
        if plausible_config and hard_errors <= 1:
            result["ok"] = True
            result["reason"] = "integridade validada por heuristica (firmware legado)"
            result["markers_found"] = ["heuristic_legacy"]
            return result
        result["reason"] = "conteudo sem marcadores esperados para o tipo de equipamento"
        return result

    # Device types sem markers mapeados — aceitar se passou critérios mínimos
    if not expected:
        result["ok"] = True
        result["reason"] = "integridade validada (sem markers especificos para este tipo)"
        return result

    result["ok"] = True
    result["reason"] = "integridade validada"
    return result

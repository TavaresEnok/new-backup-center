import re


USELESS_DETAIL_PATTERNS = (
    r"<class 'pexpect\.exceptions\.EOF'>",
    r"<class 'pexpect\.exceptions\.TIMEOUT'>",
    r"<class 'EOFError'>",
)


DETAIL_REPLACEMENTS = (
    (r"<class 'pexpect\.exceptions\.EOF'>", "conexao encerrada antes do login/banner"),
    (r"pexpect\.exceptions\.EOF", "conexao encerrada antes do login/banner"),
    (r"<class 'pexpect\.exceptions\.TIMEOUT'>", "tempo esgotado aguardando resposta do equipamento"),
    (r"pexpect\.exceptions\.TIMEOUT", "tempo esgotado aguardando resposta do equipamento"),
    (r"<class 'EOFError'>", "conexao encerrada pelo equipamento"),
    (r"EOFError", "conexao encerrada pelo equipamento"),
    (r"NetmikoTimeoutException", "tempo esgotado na conexao com o equipamento"),
    (r"NetmikoAuthenticationException", "falha de autenticacao no equipamento"),
    (r"ReadTimeout", "tempo esgotado aguardando resposta do equipamento"),
    (r"ParamikoAuthenticationException", "falha de autenticacao SSH"),
    (r"SSHException", "falha na negociacao SSH"),
)


FRIENDLY_ERROR_PATTERNS = (
    (
        (
            "incompatible ssh peer",
            "no acceptable kex algorithm",
            "kex algorithm",
        ),
        "SSH incompativel: o equipamento usa algoritmo antigo de troca de chaves que nao foi aceito nesta conexao.",
    ),
    (
        (
            "no matching cipher",
            "no acceptable ciphers",
            "cipher",
        ),
        "SSH incompativel: o equipamento usa cifra/criptografia que nao foi aceita nesta conexao.",
    ),
    (
        (
            "error reading ssh protocol banner",
            "ssh protocol banner",
        ),
        "A porta abriu, mas nao apresentou banner SSH valido. Confira se a porta/protocolo cadastrados estao corretos.",
    ),
    (
        (
            "connection refused",
            "errno 111",
        ),
        "A porta recusou a conexao. Confira porta, NAT, firewall ou servico remoto.",
    ),
    (
        (
            "no route to host",
            "network is unreachable",
            "unable to connect",
        ),
        "Nao ha rota/acesso de rede ate o equipamento.",
    ),
    (
        (
            "authentication failed",
            "login failed",
            "permission denied",
            "bad username",
            "bad password",
        ),
        "Credenciais recusadas pelo equipamento.",
    ),
    (
        (
            "pattern not detected",
            "prompt not detected",
        ),
        "O equipamento conectou, mas nao apresentou o prompt esperado para continuar o backup.",
    ),
    (
        (
            "timed out",
            "timeout",
        ),
        "Tempo esgotado aguardando resposta do equipamento.",
    ),
    (
        (
            "connection reset by peer",
            "closed by remote host",
            "transport shut down or saw eof",
        ),
        "A conexao foi encerrada pelo equipamento durante a tentativa.",
    ),
)


def _extract_attempted_profiles(text: str) -> list[str]:
    profiles = []
    detail_text = re.split(r"\bDetalhes?:", text or "", maxsplit=1, flags=re.I)[-1]
    for part in re.split(r";\s*", detail_text or ""):
        match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*:", part)
        if match:
            name = match.group(1)
            if name and name not in profiles:
                profiles.append(name)
    return profiles[:6]


def _friendly_detail_for(text: str) -> str | None:
    low = (text or "").lower()
    for markers, friendly in FRIENDLY_ERROR_PATTERNS:
        if any(marker in low for marker in markers):
            profiles = _extract_attempted_profiles(text)
            if profiles:
                return f"{friendly} Perfis de conexao testados: {', '.join(profiles)}."
            return friendly
    return None


def sanitize_operational_message(message) -> str:
    """Convert internal exception names into operator-friendly text."""
    text = str(message or "")
    if not text:
        return text

    text = re.sub(r"\x1B\[[0-9;?]*[A-Za-z]", "", text)
    text = re.sub(r".\x08", "", text)
    text = re.sub(r"(?i)\b(PGPASSWORD|MYSQL_PWD)=('([^']*)'|\S+)", r"\1=***", text)
    text = re.sub(r"(?i)(--password=|-p)'?[^'\s]+", r"\1***", text)

    friendly_detail = _friendly_detail_for(text)
    if friendly_detail:
        prefix = re.split(r"\bDetalhes?:", text, maxsplit=1, flags=re.I)[0].strip()
        if not prefix:
            prefix = "Falha durante a operacao."
        text = f"{prefix} Detalhe: {friendly_detail}"

    for pattern, replacement in DETAIL_REPLACEMENTS:
        text = re.sub(pattern, replacement, text)

    # If the only "Detalhe" was an internal class name, keep the message short.
    for pattern in USELESS_DETAIL_PATTERNS:
        text = re.sub(rf"\s*Detalhe:\s*{pattern}\s*\.?", "", text)

    text = text.replace("despositivo", "dispositivo")
    text = re.sub(r"\s+", " ", text).strip()
    return text

"""
Helpers para resolver o modo de conexao efetivo de um grupo.

Evita ambiguidades quando existem campos legados misturados
(ex.: connection_type='jump_host' mas uses_vpn=True antigo).
"""


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "on", "yes", "sim"}


def _normalize_connection_type_value(value: str) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"jump", "jump_host"}:
        return "jump_host"
    if raw in {"vpn", "direct"}:
        return raw
    return ""


def _normalized_connection_type(group) -> str:
    if not group:
        return ""
    raw = getattr(group, "connection_type", None)
    return _normalize_connection_type_value(raw)


def _normalized_device_connection_override(device) -> str:
    if not device:
        return ""

    subgroup = getattr(device, "subgroup", None)
    if subgroup and bool(getattr(subgroup, "is_active", True)):
        subgroup_type = _normalize_connection_type_value(getattr(subgroup, "connection_type", None))
        if subgroup_type:
            return subgroup_type

    extra = getattr(device, "extra_parameters", None) or {}
    if not isinstance(extra, dict):
        return ""

    override = _normalize_connection_type_value(
        extra.get("connection_subgroup_type") or extra.get("subgroup_connection_type")
    )
    enabled = _truthy(
        extra.get("connection_subgroup_enabled")
        if "connection_subgroup_enabled" in extra
        else extra.get("subgroup_connection_enabled")
    )

    # Compatibilidade: se o tipo foi definido manualmente no JSON,
    # assume override ativo mesmo sem flag booleana.
    if override and (enabled or "connection_subgroup_type" in extra or "subgroup_connection_type" in extra):
        return override
    return ""


def get_effective_connection_type(group, device=None) -> str:
    override = _normalized_device_connection_override(device)
    if override:
        return override

    if not group:
        return ""

    conn_type = _normalized_connection_type(group)
    if conn_type:
        return conn_type

    # Fallback para dados legados sem connection_type consistente.
    if bool(getattr(group, "uses_jump_host", False)):
        return "jump_host"
    if bool(getattr(group, "uses_vpn", False)):
        return "vpn"
    return "direct"


def uses_jump_host(group, device=None) -> bool:
    return get_effective_connection_type(group, device=device) == "jump_host"


def uses_vpn_tunnel(group, device=None) -> bool:
    return get_effective_connection_type(group, device=device) == "vpn"

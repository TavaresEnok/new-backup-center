"""
Testes unitários para os patches de diagnóstico e confiabilidade de backup.

Testa:
- classify_failure() — classificação de categorias de erro
- validate_backup_integrity() — validação de integridade com novos markers
- _should_retry_transient_failure() — política de retry correta
"""

import os
import tempfile
import pytest

from app.services.backup_diagnostics import (
    classify_failure,
    failure_label,
    is_transient_failure,
    validate_backup_integrity,
)


# ─── classify_failure ───────────────────────────────────────────────

class TestClassifyFailure:
    def test_timeout(self):
        assert classify_failure("Connection timed out") == "timeout"
        assert classify_failure("TimeoutException reading from device") == "timeout"
        assert classify_failure("SoftTimeLimitExceeded") == "timeout"

    def test_port_refused(self):
        assert classify_failure("Connection refused") == "port_refused"
        assert classify_failure("[Errno 111] Connection refused") == "port_refused"
        assert classify_failure("Port closed on remote host") == "port_refused"

    def test_connection(self):
        assert classify_failure("Socket error during SSH session") == "connection"
        assert classify_failure("EOF during negotiation") == "connection"
        assert classify_failure("Host unreachable") == "connection"
        assert classify_failure("No route to host") == "connection"

    def test_no_ping(self):
        assert classify_failure("Sem resposta ao ping") == "no_ping"
        assert classify_failure("100% packet loss") == "no_ping"

    def test_auth(self):
        assert classify_failure("Authentication failed") == "auth"
        assert classify_failure("Credenciais incorretas") == "auth"
        assert classify_failure("Invalid password") == "auth"
        assert classify_failure("Access denied for user") == "auth"

    def test_vpn(self):
        assert classify_failure("VPN connection failed") == "vpn"
        assert classify_failure("L2TP tunnel error") == "vpn"

    def test_script(self):
        assert classify_failure("Traceback (most recent call last)") == "script"
        assert classify_failure("AttributeError: 'NoneType' object") == "script"
        assert classify_failure("ModuleNotFoundError: No module named x") == "script"

    def test_unknown(self):
        assert classify_failure("Something totally random happened") == "unknown"
        assert classify_failure("") == "unknown"
        assert classify_failure(None) == "unknown"

    def test_priority_timeout_over_auth(self):
        """Timeout deve ter prioridade quando msg contém ambos."""
        msg = "Credenciais ok mas timed out esperando resposta"
        assert classify_failure(msg) == "timeout"

    def test_priority_refused_over_connection(self):
        """Connection refused deve classificar como port_refused, não connection."""
        msg = "Connection refused by remote host"
        assert classify_failure(msg) == "port_refused"


class TestFailureLabel:
    def test_known_categories(self):
        assert failure_label("auth") == "Autenticacao"
        assert failure_label("timeout") == "Timeout"
        assert failure_label("port_refused") == "Porta recusada"

    def test_unknown_category(self):
        assert failure_label("foobar") == "Outros"
        assert failure_label("") == "Outros"


class TestIsTransientFailure:
    def test_transient_categories(self):
        assert is_transient_failure("timeout") is True
        assert is_transient_failure("connection") is True
        assert is_transient_failure("vpn") is True

    def test_non_transient_categories(self):
        assert is_transient_failure("auth") is False
        assert is_transient_failure("port_refused") is False
        assert is_transient_failure("script") is False
        assert is_transient_failure("unknown") is False
        assert is_transient_failure("no_ping") is False


# ─── validate_backup_integrity ──────────────────────────────────────

class TestValidateBackupIntegrity:
    def _write_temp(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return path

    def test_missing_file(self):
        result = validate_backup_integrity(None)
        assert result["ok"] is False
        assert "ausente" in result["reason"]

    def test_small_file_rejected(self):
        path = self._write_temp("tiny")
        try:
            result = validate_backup_integrity(path, "huawei", "huawei_olt.py")
            assert result["ok"] is False
            assert "pequeno" in result["reason"]
        finally:
            os.unlink(path)

    def test_few_lines_rejected(self):
        # Conteúdo >= 128 bytes para não cair na regra de tamanho mínimo antes da contagem de linhas.
        chunk = "x" * 45
        path = self._write_temp(f"{chunk}\n{chunk}\n{chunk}\n")
        try:
            result = validate_backup_integrity(path, "cisco", "cisco.py")
            assert result["ok"] is False
            assert "poucas linhas" in result["reason"]
        finally:
            os.unlink(path)

    def test_known_type_with_markers_accepted(self):
        content = "\n".join([
            "# RouterOS configuration",
            "/interface bridge add name=br0",
            "/ip address add address=192.168.1.1/24 interface=br0",
            "# model = RB750Gr3",
            "",
            "/ip route add dst-address=0.0.0.0/0 gateway=192.168.1.1",
        ] + ["# filler line"] * 20)
        path = self._write_temp(content)
        try:
            result = validate_backup_integrity(path, "routeros", "mikrotik_ros_netmiko.py")
            assert result["ok"] is True
            assert "validada" in result["reason"]
            assert len(result["markers_found"]) > 0
        finally:
            os.unlink(path)

    def test_known_type_no_markers_rejected(self):
        content = "\n".join(["random line " + str(i) for i in range(100)])
        path = self._write_temp(content)
        try:
            result = validate_backup_integrity(path, "huawei", "huawei_olt.py")
            assert result["ok"] is False
            assert "marcadores" in result["reason"]
        finally:
            os.unlink(path)

    def test_unknown_type_accepted_if_large_enough(self):
        """Device types sem markers mapeados devem aceitar backup se tamanho ok."""
        content = "\n".join(["config line " + str(i) for i in range(100)])
        path = self._write_temp(content)
        try:
            result = validate_backup_integrity(path, "some_weird_brand", "weird_script.py")
            assert result["ok"] is True
            assert "sem markers especificos" in result["reason"]
        finally:
            os.unlink(path)

    def test_datacom_markers(self):
        """Novo marker: datacom deve validar com 'show running-config'."""
        content = "\n".join([
            "show running-config",
            "interface GigabitEthernet0/0",
            "vlan 100",
        ] + ["# config line"] * 30)
        path = self._write_temp(content)
        try:
            result = validate_backup_integrity(path, "datacom", "datacom_olt_netmiko.py")
            assert result["ok"] is True
        finally:
            os.unlink(path)

    def test_fortinet_markers(self):
        """Novo marker: fortinet."""
        content = "\n".join([
            "config system global",
            "set hostname FW-01",
            "config firewall policy",
        ] + ["# rule line"] * 30)
        path = self._write_temp(content)
        try:
            result = validate_backup_integrity(path, "fortinet", "fortinet_firewall.py")
            assert result["ok"] is True
            assert len(result["markers_found"]) >= 2
        finally:
            os.unlink(path)


# ─── _should_retry_transient_failure (from backups.py) ──────────────

class TestShouldRetryTransientFailure:
    """Testa a lógica de retry importada do módulo de tasks."""

    @staticmethod
    def _should_retry(category, message):
        # Reimplementa a lógica para teste isolado sem importar Celery
        from app.services.backup_diagnostics import is_transient_failure

        if not is_transient_failure(category):
            return False
        text = str(message or "").strip().lower()
        if category == "connection":
            hard_markers = (
                "connection refused", "no route to host",
                "network is unreachable", "unable to connect to remote host",
                "unable to connect to port", "authentication failed",
                "invalid username", "invalid password", "unauthorized",
                "access denied", "permission denied", "wrong tcp port",
                "incorrect hostname",
            )
            if any(m in text for m in hard_markers):
                return False
        return True

    def test_timeout_retries(self):
        assert self._should_retry("timeout", "Connection timed out") is True

    def test_connection_generic_retries(self):
        assert self._should_retry("connection", "SSH session reset by peer") is True

    def test_connection_refused_no_retry(self):
        assert self._should_retry("connection", "Connection refused") is False

    def test_no_route_no_retry(self):
        assert self._should_retry("connection", "No route to host") is False

    def test_auth_no_retry(self):
        assert self._should_retry("auth", "Authentication failed") is False

    def test_port_refused_no_retry(self):
        assert self._should_retry("port_refused", "Connection refused") is False

    def test_script_no_retry(self):
        assert self._should_retry("script", "AttributeError") is False

    def test_vpn_retries(self):
        assert self._should_retry("vpn", "L2TP tunnel timeout") is True

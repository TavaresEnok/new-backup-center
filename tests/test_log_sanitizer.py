from app.utils.log_sanitizer import sanitize_operational_message


def test_sanitize_pexpect_eof_detail():
    msg = "Falha de conectividade com o dispositivo. Detalhe: <class 'pexpect.exceptions.EOF'>"

    sanitized = sanitize_operational_message(msg)

    assert sanitized == "Falha de conectividade com o dispositivo. Detalhe: conexao encerrada antes do login/banner"
    assert "pexpect" not in sanitized
    assert "<class" not in sanitized


def test_sanitize_pexpect_timeout_detail():
    msg = "Falha de conectividade com o dispositivo. Detalhe: <class 'pexpect.exceptions.TIMEOUT'>"

    sanitized = sanitize_operational_message(msg)

    assert "tempo esgotado" in sanitized.lower()
    assert "pexpect" not in sanitized


def test_sanitize_netmiko_paramiko_kex_details():
    msg = (
        "Falha de conectividade com o dispositivo. Detalhes: "
        "huawei: NetmikoTimeoutException: A paramiko SSHException occurred during connection creation: "
        "Incompatible ssh peer (no acceptable kex algorithm); "
        "cisco_ios: NetmikoTimeoutException: A paramiko SSHException occurred during connection creation: "
        "Incompatible ssh peer (no acceptable kex algorithm); "
        "tplink_jetstream: NetmikoTimeoutException: A paramiko SSHException occurred during connection creation: "
        "Incompatible ssh peer (no acceptable kex algorithm)"
    )

    sanitized = sanitize_operational_message(msg)

    assert sanitized == (
        "Falha de conectividade com o dispositivo. "
        "Detalhe: SSH incompativel: o equipamento usa algoritmo antigo de troca de chaves "
        "que nao foi aceito nesta conexao. Tentativas realizadas: huawei, cisco_ios, tplink_jetstream."
    )
    assert "Netmiko" not in sanitized
    assert "SSHException" not in sanitized
    assert "paramiko" not in sanitized.lower()


def test_sanitize_connection_refused_details():
    msg = "Falha de conectividade com o dispositivo. Detalhes: cisco_ios: NetmikoTimeoutException: [Errno 111] Connection refused"

    sanitized = sanitize_operational_message(msg)

    assert "A porta recusou a conexao" in sanitized
    assert "cisco_ios" in sanitized
    assert "Netmiko" not in sanitized

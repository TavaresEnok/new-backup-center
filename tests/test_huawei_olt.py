import importlib
import pathlib
import re
import sys


SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "scripts" / "backup_scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

huawei_olt = importlib.import_module("huawei_olt")


class FakeHuaweiChild:
    def __init__(self):
        self.before = ""
        self.sent_lines = []
        self._expects = [
            (2, "display saved-configuration\n"),
            (
                0,
                "sysname OLT-MEGAMIDIA\n"
                "vlan 100 smart\n"
                "interface gpon 0/1\n"
                " service-port 1 vlan 100 gpon 0/1/0 ont 1 gemport 1 multi-service user-vlan 100\n"
                "return\n"
                "OLT-MEGAMIDIA(config)#",
            ),
        ]

    def sendline(self, value):
        self.sent_lines.append(value)

    def send(self, value):
        self.sent_lines.append(value)

    def expect(self, *_args, **_kwargs):
        idx, before = self._expects.pop(0)
        self.before = before
        return idx


class DummyChild:
    def __init__(self):
        self.sent_lines = []

    def sendline(self, value):
        self.sent_lines.append(value)

    def expect(self, *_args, **_kwargs):
        return 0


class EofBeforeLoginChild:
    def __init__(self, before=""):
        self.before = before
        self.after = ""
        self.sent_lines = []

    def sendline(self, value):
        self.sent_lines.append(value)

    def expect(self, *_args, **_kwargs):
        return 8


def test_huawei_send_collect_answers_cr_interactive_prompt_without_colon():
    child = FakeHuaweiChild()

    ok, output = huawei_olt._send_and_collect(child, "display saved-configuration", timeout_seconds=30)

    assert ok is True
    assert child.sent_lines == ["display saved-configuration", ""]
    assert "sysname OLT-MEGAMIDIA" in output


def test_huawei_prompt_regex_does_not_match_config_section_markers():
    assert re.search(huawei_olt.PROMPT_COMMAND_LINE, "OLT-MEGAMIDIA(config)#\n")
    assert re.search(huawei_olt.PROMPT_COMMAND_LINE, "MA5608T-JACARAU#\n")
    assert re.search(huawei_olt.PROMPT_COMMAND_LINE, "<MA5800X7>\n")
    assert re.search(huawei_olt.PROMPT_COMMAND_LINE, "<OLT-MEGAMIDIA>\n")
    assert not re.search(huawei_olt.PROMPT_COMMAND_LINE, "#\n")
    assert not re.search(huawei_olt.PROMPT_COMMAND_LINE, "[device-config]\n")
    assert not re.search(huawei_olt.PROMPT_COMMAND_LINE, "[gpon]\n")
    assert not re.search(huawei_olt.PROMPT_COMMAND_LINE, "<global-config>\n")
    assert not re.search(huawei_olt.PROMPT_COMMAND_LINE, "<gpon-0/1>\n")
    assert not re.search(huawei_olt.PROMPT_COMMAND_LINE, "<bbs-config>\n")
    assert not re.search(huawei_olt.PROMPT_COMMAND_LINE, "  <global-config>\n")


def test_huawei_login_eof_before_banner_returns_useful_reason():
    child = EofBeforeLoginChild()

    ok, reason = huawei_olt._login(child, "root", "secret", timeout=1)

    assert ok is False
    assert "Conexao encerrada antes" in reason
    assert "<class" not in reason


def test_huawei_olt_uses_saved_configuration_after_invalid_variants(monkeypatch, tmp_path):
    monkeypatch.setattr(huawei_olt, "open_pexpect_session", lambda *_args, **_kwargs: DummyChild())
    monkeypatch.setattr(huawei_olt, "_login", lambda *_args, **_kwargs: (True, ""))
    monkeypatch.setattr(huawei_olt, "_try_enable", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(huawei_olt, "close_pexpect_session", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(huawei_olt, "prepare_backup_path", lambda *_args, **_kwargs: str(tmp_path / "huawei.cfg"))

    seen = []

    def fake_collect(_child, command, **_kwargs):
        seen.append(command)
        if command in {"config", "screen-length 0 temporary"}:
            return True, ""
        if command == "display saved-configuration":
            return True, (
                "display saved-configuration\n"
                "sysname OLT-MEGAMIDIA\n"
                "vlan 100 smart\n"
                "interface gpon 0/1\n"
                " service-port 1 vlan 100 gpon 0/1/0 ont 1 gemport 1 multi-service user-vlan 100\n"
                "return\n"
            )
        return True, (
            f"{command}\n"
            "                                                    ^\n"
            "  % Too many parameters, the error locates at '^'\n"
        )

    monkeypatch.setattr(huawei_olt, "_send_and_collect", fake_collect)

    result = huawei_olt.realizar_backup(
        ip="10.12.107.2",
        usuario="admin",
        porta=22,
        nome_provedor="Ponte Digital",
        nome_tipo_equip="Huawei OLT",
        nome_dispositivo="OLT-MEGAMIDIA",
        parametros={"password": "secret"},
    )

    assert result[0] is True
    assert "display saved-configuration" in seen
    content = (tmp_path / "huawei.cfg").read_text(encoding="utf-8")
    assert "sysname OLT-MEGAMIDIA" in content
    assert "Too many parameters" not in content


def test_huawei_olt_does_not_accept_short_pre_config_as_backup(monkeypatch, tmp_path):
    monkeypatch.setattr(huawei_olt, "open_pexpect_session", lambda *_args, **_kwargs: DummyChild())
    monkeypatch.setattr(huawei_olt, "_login", lambda *_args, **_kwargs: (True, ""))
    monkeypatch.setattr(huawei_olt, "_try_enable", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(huawei_olt, "close_pexpect_session", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(huawei_olt, "prepare_backup_path", lambda *_args, **_kwargs: str(tmp_path / "huawei-preconfig.cfg"))

    seen = []
    short_preconfig = (
        "<pre-config>\n"
        " board-template start H902GPHF\n"
        " board-template start H902GPSF\n"
        " board add 0/1 H901GPHF\n"
        " board add 0/2 H902GPHF\n"
        " board add 0/3 H902GPSF\n"
        " board add 0/20 H901PILA\n"
        " board add 0/21 H901PILA\n"
        "#\n"
    )

    def fake_collect(_child, command, **_kwargs):
        seen.append(command)
        if command in {"config", "screen-length 0 temporary"}:
            return True, ""
        if command in {"display current-configuration", "display current-configuration simple"}:
            return True, short_preconfig
        if command == "display saved-configuration":
            return True, (
                "display saved-configuration\n"
                "sysname OLT-MEGAMIDIA\n"
                "vlan 100 smart\n"
                "interface gpon 0/1\n"
                " service-port 1 vlan 100 gpon 0/1/0 ont 1 gemport 1 multi-service user-vlan 100\n"
                "return\n"
            )
        return True, (
            f"{command}\n"
            "                                                    ^\n"
            "  % Too many parameters, the error locates at '^'\n"
        )

    monkeypatch.setattr(huawei_olt, "_send_and_collect", fake_collect)

    result = huawei_olt.realizar_backup(
        ip="10.12.107.2",
        usuario="admin",
        porta=22,
        nome_provedor="Ponte Digital",
        nome_tipo_equip="Huawei OLT",
        nome_dispositivo="OLT-MEGAMIDIA",
        parametros={"password": "secret"},
    )

    assert result[0] is True
    assert seen.index("display saved-configuration") > seen.index("display current-configuration")
    content = (tmp_path / "huawei-preconfig.cfg").read_text(encoding="utf-8")
    assert "sysname OLT-MEGAMIDIA" in content
    assert "<pre-config>" not in content


def test_huawei_olt_rejects_pure_error_outputs(monkeypatch, tmp_path):
    monkeypatch.setattr(huawei_olt, "open_pexpect_session", lambda *_args, **_kwargs: DummyChild())
    monkeypatch.setattr(huawei_olt, "_login", lambda *_args, **_kwargs: (True, ""))
    monkeypatch.setattr(huawei_olt, "_try_enable", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(huawei_olt, "close_pexpect_session", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(huawei_olt, "prepare_backup_path", lambda *_args, **_kwargs: str(tmp_path / "huawei-error.cfg"))

    def fake_collect(_child, command, **_kwargs):
        if command in {"config", "screen-length 0 temporary"}:
            return True, ""
        return True, (
            f"{command}\n"
            "                                                    ^\n"
            "  % Too many parameters, the error locates at '^'\n"
        )

    monkeypatch.setattr(huawei_olt, "_send_and_collect", fake_collect)

    result = huawei_olt.realizar_backup(
        ip="10.12.107.2",
        usuario="admin",
        porta=22,
        nome_provedor="Ponte Digital",
        nome_tipo_equip="Huawei OLT",
        nome_dispositivo="OLT-MEGAMIDIA",
        parametros={"password": "secret"},
    )

    assert result[0] is False
    assert "curta/vazia" in result[1]
    assert not (tmp_path / "huawei-error.cfg").exists()


def test_huawei_olt_does_not_save_timeout_partial_config(monkeypatch, tmp_path):
    monkeypatch.setattr(huawei_olt, "open_pexpect_session", lambda *_args, **_kwargs: DummyChild())
    monkeypatch.setattr(huawei_olt, "_login", lambda *_args, **_kwargs: (True, ""))
    monkeypatch.setattr(huawei_olt, "_try_enable", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(huawei_olt, "close_pexpect_session", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(huawei_olt, "prepare_backup_path", lambda *_args, **_kwargs: str(tmp_path / "huawei-partial.cfg"))

    partial_config = (
        "display current-configuration\n"
        "sysname OLT-MEGAMIDIA\n"
        "vlan 100 smart\n"
        "interface gpon 0/1\n"
        " service-port 6488 vlan 554 gpon 0/1/4 ont 73 gemport 554 multi-service\n"
        "user-vlan 554 tag-transform transla"
    )

    def fake_collect(_child, command, **_kwargs):
        if command in {"config", "screen-length 0 temporary", "mmi-mode original-output"}:
            return True, ""
        return False, partial_config

    monkeypatch.setattr(huawei_olt, "_send_and_collect", fake_collect)

    result = huawei_olt.realizar_backup(
        ip="10.12.107.2",
        usuario="admin",
        porta=22,
        nome_provedor="Ponte Digital",
        nome_tipo_equip="Huawei OLT",
        nome_dispositivo="OLT-MEGAMIDIA",
        parametros={"password": "secret"},
    )

    assert result[0] is False
    assert "Retornos incompletos ignorados" in result[1]
    assert not (tmp_path / "huawei-partial.cfg").exists()

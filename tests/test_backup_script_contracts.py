import ast
import importlib.util
import inspect
import re
import sys
from pathlib import Path

import pytest

from app.services.backup_executor import _filter_script_kwargs


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "app" / "scripts" / "backup_scripts"
HELPER_SCRIPTS = {
    "__init__.py",
    "generic_netmiko_profiles.py",
    "olt_cli_backup.py",
    "script_helpers.py",
}
OPTIONAL_RUNTIME_DEPS = {
    "netmiko",
    "paramiko",
    "pexpect",
}
SCRIPT_REFERENCE_FILES = [
    Path("populate_types.py"),
    Path("scripts/migrate_legacy_local_to_new.py"),
    Path("scripts/migrate_old_system_full.py"),
]


def _active_backup_scripts() -> list[Path]:
    return [
        path
        for path in sorted(SCRIPTS_DIR.glob("*.py"))
        if path.name not in HELPER_SCRIPTS
    ]


def _realizar_backup_node(tree: ast.Module) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "realizar_backup":
            return node
    return None


@pytest.mark.parametrize("script_path", _active_backup_scripts(), ids=lambda path: path.name)
def test_backup_scripts_have_required_contract(script_path: Path):
    tree = ast.parse(script_path.read_text(encoding="utf-8"), filename=str(script_path))
    function = _realizar_backup_node(tree)

    assert function is not None, f"{script_path.name} precisa definir realizar_backup"
    assert function.args.kwarg is not None, (
        f"{script_path.name} precisa aceitar **kwargs para compatibilidade com BackupExecutor"
    )


@pytest.mark.parametrize("script_path", _active_backup_scripts(), ids=lambda path: path.name)
def test_backup_scripts_import_when_runtime_dependencies_exist(script_path: Path):
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))

    spec = importlib.util.spec_from_file_location(script_path.stem, script_path)
    assert spec is not None and spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except ModuleNotFoundError as exc:
        if exc.name in OPTIONAL_RUNTIME_DEPS:
            pytest.skip(f"Dependencia opcional ausente no ambiente de teste: {exc.name}")
        raise

    backup_fn = getattr(module, "realizar_backup", None)
    assert callable(backup_fn), f"{script_path.name} precisa expor realizar_backup"

    signature = inspect.signature(backup_fn)
    assert any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    ), f"{script_path.name} precisa aceitar **kwargs para compatibilidade com BackupExecutor"


def test_seed_and_migration_script_names_point_to_existing_files():
    missing = []
    root_dir = SCRIPTS_DIR.parents[2]

    for relative_path in SCRIPT_REFERENCE_FILES:
        file_path = root_dir / relative_path
        if not file_path.exists():
            continue

        content = file_path.read_text(encoding="utf-8")
        script_names = set(re.findall(r"['\"]([^'\"]+\.py)['\"]", content))
        for script_name in sorted(script_names):
            if script_name.startswith("__"):
                continue
            if any(char in script_name for char in "*?[]"):
                continue
            if not (SCRIPTS_DIR / script_name).is_file():
                missing.append(f"{relative_path}: {script_name}")

    assert not missing, "Scripts referenciados em seeds/migrações não existem:\n" + "\n".join(missing)


def test_executor_keeps_all_kwargs_for_current_script_contract():
    def modern(ip, **kwargs):
        return ip, kwargs

    original = {"ip": "10.0.0.1", "logger": object(), "task_id": "task-1"}
    filtered, ignored = _filter_script_kwargs(modern, original)

    assert filtered is original
    assert ignored == []


def test_executor_filters_extra_kwargs_for_legacy_script():
    def legacy(ip, usuario, porta):
        return ip, usuario, porta

    filtered, ignored = _filter_script_kwargs(
        legacy,
        {
            "ip": "10.0.0.1",
            "usuario": "admin",
            "porta": 22,
            "logger": "log",
            "task_id": "task",
        },
    )

    assert filtered == {"ip": "10.0.0.1", "usuario": "admin", "porta": 22}
    assert ignored == ["logger", "task_id"]

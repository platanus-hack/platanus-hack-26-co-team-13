from pathlib import Path

import os
import subprocess
import sys
import stat

from memory_firewall.cli import (
    ADAPTER_INSTALL_COMMANDS,
    ADAPTER_TARGETS,
    CLI_INSTALL_COMMAND,
    ensure_signing_key,
    install_adapter,
)


def test_install_adapter_copies_runtime_entrypoints(tmp_path: Path) -> None:
    expected = {
        "pi": "index.ts",
        "hermes": "__init__.py",
        "openclaw": "openclaw.plugin.json",
    }
    for agent, entrypoint in expected.items():
        destination = install_adapter(agent, "project", tmp_path / agent)
        assert (destination / entrypoint).is_file()
        assert not (destination / "README.md").exists()


def test_module_cli_installs_each_adapter(tmp_path: Path) -> None:
    expected = {
        "pi": "index.ts",
        "hermes": "plugin.yaml",
        "openclaw": "package.json",
    }
    for agent, entrypoint in expected.items():
        target = tmp_path / agent
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "memory_firewall.cli",
                "install",
                agent,
                "--target",
                str(target),
            ],
            cwd=Path(__file__).parents[1],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert (target / entrypoint).is_file()
        assert f"Installed {agent} adapter" in result.stdout


def test_dashboard_commands_are_executable_and_use_official_plugin_roots() -> None:
    assert CLI_INSTALL_COMMAND.startswith('PYTHON_BIN="$(command -v python3.14')
    assert "Python 3.11+ is required" in CLI_INSTALL_COMMAND
    assert '"$PYTHON_BIN" -m venv ~/.memory-firewall/venv' in CLI_INSTALL_COMMAND
    assert "#subdirectory=backend" in CLI_INSTALL_COMMAND
    assert ADAPTER_INSTALL_COMMANDS["pi"].startswith("pi --version")
    assert "memory-firewall install pi" in ADAPTER_INSTALL_COMMANDS["pi"]
    assert ADAPTER_INSTALL_COMMANDS["hermes"].startswith("hermes --version")
    assert "hermes plugins enable memory-firewall" in ADAPTER_INSTALL_COMMANDS["hermes"]
    assert ADAPTER_INSTALL_COMMANDS["openclaw"].startswith("openclaw --version")
    assert "openclaw plugins install --force" in ADAPTER_INSTALL_COMMANDS["openclaw"]
    assert "openclaw gateway install --force" in ADAPTER_INSTALL_COMMANDS["openclaw"]
    assert ADAPTER_TARGETS["openclaw"]["user"].parts[-3:] == (
        ".memory-firewall",
        "adapters",
        "openclaw",
    )


def test_signing_key_is_created_once_with_owner_only_permissions(tmp_path: Path) -> None:
    key_path = tmp_path / "state" / "signing.key"

    first = ensure_signing_key(key_path)
    second = ensure_signing_key(key_path)

    assert first == second
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_persistent_server_rejects_ephemeral_signing_key(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment.pop("MEMORY_FIREWALL_ED25519_PRIVATE_KEY", None)
    environment["MEMORY_FIREWALL_DB_PATH"] = str(tmp_path / "persistent.sqlite3")

    result = subprocess.run(
        [sys.executable, "-c", "import api.main"],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "Persistent SQLite requires MEMORY_FIREWALL_ED25519_PRIVATE_KEY" in result.stderr


def test_cli_provisions_key_before_importing_server(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment.pop("MEMORY_FIREWALL_ED25519_PRIVATE_KEY", None)
    environment["MEMORY_FIREWALL_DB_PATH"] = str(tmp_path / "persistent.sqlite3")
    key_path = tmp_path / "signing.key"
    program = """
import importlib
import sys
import uvicorn
from memory_firewall.cli import main

uvicorn.run = lambda *_args, **_kwargs: importlib.import_module("api.main")
sys.argv = ["memory-firewall", "serve", "--key-file", sys.argv[1]]
main()
"""

    result = subprocess.run(
        [sys.executable, "-c", program, str(key_path)],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert key_path.is_file()

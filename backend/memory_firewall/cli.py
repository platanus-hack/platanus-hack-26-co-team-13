"""Command-line installation and local service entry points."""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import secrets
import shutil
from importlib.resources import files
from pathlib import Path


ADAPTER_TARGETS = {
    "pi": {
        "user": Path.home() / ".pi/agent/extensions/provenance-firewall",
        "project": Path(".pi/extensions/provenance-firewall"),
    },
    "hermes": {
        "user": Path.home() / ".hermes/plugins/memory-firewall",
        "project": Path(".hermes/plugins/memory-firewall"),
    },
    "openclaw": {
        "user": Path.home() / ".memory-firewall/adapters/openclaw",
        "project": Path(".memory-firewall/adapters/openclaw"),
    },
}

PACKAGE_SPEC = (
    "git+https://github.com/platanus-hack/"
    "platanus-hack-26-co-team-13.git#subdirectory=backend"
)
VENV_PYTHON = "~/.memory-firewall/venv/bin/python"
VENV_CLI = "~/.memory-firewall/venv/bin/memory-firewall"
PYTHON_SELECTOR = (
    'PYTHON_BIN="$(command -v python3.14 || command -v python3.13 || '
    'command -v python3.12 || command -v python3.11 || command -v python3)"'
)
CLI_INSTALL_COMMAND = (
    PYTHON_SELECTOR
    + " && \"$PYTHON_BIN\" -c 'import sys; raise SystemExit("
    '"Python 3.11+ is required" if sys.version_info < (3, 11) else 0)\''
    + ' && "$PYTHON_BIN" -m venv ~/.memory-firewall/venv'
    f' && {VENV_PYTHON} -m pip install "{PACKAGE_SPEC}"'
)
ADAPTER_INSTALL_COMMANDS = {
    "pi": f"pi --version >/dev/null && {VENV_CLI} install pi",
    "hermes": (
        "hermes --version >/dev/null"
        f" && {VENV_CLI} install hermes"
        " && hermes plugins enable memory-firewall"
    ),
    "openclaw": (
        "openclaw --version >/dev/null"
        f" && {VENV_CLI} install openclaw"
        " && openclaw plugins install --force ~/.memory-firewall/adapters/openclaw"
        " && openclaw gateway install --force"
        " && openclaw gateway restart"
    ),
}


def ensure_signing_key(path: Path) -> str:
    """Load or create a private Ed25519 seed with owner-only permissions."""

    key_path = path.expanduser().resolve()
    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not key_path.exists():
        encoded = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        try:
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="ascii") as key_file:
                key_file.write(encoded)
        except FileExistsError:
            pass
    encoded = key_path.read_text(encoding="ascii").strip()
    key_path.chmod(0o600)
    try:
        seed = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError(f"Invalid signing key file: {key_path}") from exc
    if len(seed) != 32:
        raise RuntimeError(f"Signing key must contain a base64 32-byte seed: {key_path}")
    return encoded


def install_adapter(agent: str, scope: str, target: Path | None = None) -> Path:
    """Copy a bundled native adapter to an agent-owned extension directory."""

    destination = (target or ADAPTER_TARGETS[agent][scope]).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    source = files("memory_firewall.adapters").joinpath(agent)
    for entry in source.iterdir():
        if entry.name == "README.md" or entry.name == "__pycache__":
            continue
        if entry.name == "__init__.py" and agent != "hermes":
            continue
        if entry.is_file():
            with entry.open("rb") as source_file, (destination / entry.name).open("wb") as target_file:
                shutil.copyfileobj(source_file, target_file)
    return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="memory-firewall")
    subcommands = parser.add_subparsers(dest="command", required=True)

    serve = subcommands.add_parser("serve", help="Run the local firewall core")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument(
        "--key-file",
        type=Path,
        default=Path.home() / ".memory-firewall/signing.key",
    )

    install = subcommands.add_parser("install", help="Install a native agent adapter")
    install.add_argument("agent", choices=sorted(ADAPTER_TARGETS))
    install.add_argument("--scope", choices=["user", "project"], default="user")
    install.add_argument("--target", type=Path)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "serve":
        import uvicorn

        os.environ.setdefault(
            "MEMORY_FIREWALL_ED25519_PRIVATE_KEY",
            ensure_signing_key(args.key_file),
        )
        print("Control plane users register from the web interface.")
        uvicorn.run("api.main:app", host=args.host, port=args.port)
        return

    destination = install_adapter(args.agent, args.scope, args.target)
    print(f"Installed {args.agent} adapter at {destination}")
    if args.agent == "pi":
        print("Restart Pi or run /reload to load the adapter.")
    elif args.agent == "hermes":
        print("Enable it with: hermes plugins enable memory-firewall")
    elif args.agent == "openclaw":
        print(f"Install it with: openclaw plugins install --force {destination}")
        print("Then restart the Gateway: openclaw gateway restart")


if __name__ == "__main__":
    main()

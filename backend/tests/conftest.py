"""Stable, isolated process configuration for backend tests."""

from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path


os.environ.setdefault(
    "MEMORY_FIREWALL_DB_PATH",
    str(Path(tempfile.gettempdir()) / "memory-firewall-tests.sqlite3"),
)
os.environ.setdefault(
    "MEMORY_FIREWALL_ED25519_PRIVATE_KEY",
    base64.b64encode(bytes(range(32))).decode("ascii"),
)
os.environ.setdefault("MEMORY_FIREWALL_ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("MEMORY_FIREWALL_ADMIN_ACTOR_ID", "user:support-supervisor")
os.environ.setdefault("MEMORY_FIREWALL_ADMIN_TENANT_ID", "default")

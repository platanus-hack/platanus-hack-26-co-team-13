"""Core domain for the Memory Firewall MVP."""

from typing import Any

__all__ = ["MemoryFirewallService"]


def __getattr__(name: str) -> Any:
    """Keep the public service import lazy so CLI key setup runs before crypto."""

    if name == "MemoryFirewallService":
        from .service import MemoryFirewallService

        return MemoryFirewallService
    raise AttributeError(name)

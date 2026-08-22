"""Static contracts for the independently installable runtime adapters."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).parents[1] / "memory_firewall" / "adapters"


def _text(adapter: str, filename: str) -> str:
    return (ROOT / adapter / filename).read_text(encoding="ascii")


def test_required_adapter_package_files_exist() -> None:
    expected = {
        "pi": {"package.json", "index.ts", "README.md"},
        "hermes": {"plugin.yaml", "__init__.py", "README.md"},
        "openclaw": {"package.json", "openclaw.plugin.json", "index.ts", "README.md"},
    }
    for adapter, files in expected.items():
        assert files <= {path.name for path in (ROOT / adapter).iterdir()}

    assert json.loads(_text("pi", "package.json"))["pi"]["extensions"] == ["./index.ts"]
    assert json.loads(_text("openclaw", "openclaw.plugin.json"))["id"] == "memory-firewall"


def test_adapters_use_native_hooks_and_strip_reserved_metadata() -> None:
    pi = _text("pi", "index.ts")
    hermes = _text("hermes", "__init__.py")
    openclaw = _text("openclaw", "index.ts")

    assert 'pi.on("tool_call"' in pi
    assert 'pi.on("session_start"' in pi
    assert "runtime/connections/heartbeat" in pi
    assert "runtime/tool-blocks" in pi
    assert 'ctx.register_hook("pre_tool_call"' in hermes
    assert "definePluginEntry" in openclaw
    assert 'api.on("before_tool_call"' in openclaw
    assert "delete event.input._memory_firewall" in pi
    assert 'args.pop("_memory_firewall"' in hermes
    assert "delete params._memory_firewall" in openclaw


def test_adapters_are_fail_closed_and_do_not_ingest_metadata_actor() -> None:
    sources = {
        "pi": _text("pi", "index.ts"),
        "hermes": _text("hermes", "__init__.py"),
        "openclaw": _text("openclaw", "index.ts"),
    }
    for source in sources.values():
        assert "memory-firewall.tool-call.v1" in source
        assert "MEMORY_FIREWALL_TIMEOUT_MS" in source
        assert "request_id" in source
        assert "decision" in source and "review" in source and "block" in source
        assert '_memory_firewall.actor' not in source
        assert 'value.actor' not in source
        assert 'get("actor")' not in source

    assert 'decision: "block"' in sources["pi"]
    assert '"decision": "block"' in sources["hermes"]
    assert 'decision: "block"' in sources["openclaw"]
    assert "requireApproval" in sources["openclaw"]
    assert '"action": "approve"' in sources["hermes"]


def test_hermes_handler_strips_metadata_and_maps_decisions(monkeypatch) -> None:
    from memory_firewall.adapters.hermes import pre_tool_call

    monkeypatch.delenv("MEMORY_FIREWALL_UNPROTECTED_TOOLS", raising=False)
    arguments = {
        "vendor": "Andina Logistics",
        "_memory_firewall": {
            "argument_lineage": {"vendor": ["analysis_signed"]},
            "scope": "accounts_payable",
            "tenant_id": "demo",
        },
    }
    captured = {}

    def allow(payload):
        captured.update(payload)
        return {"decision": "allow", "reason": "verified"}

    result = pre_tool_call(
        "pay_invoice",
        arguments,
        task_id="session-b",
        client=allow,
    )

    assert result == {"action": "modify", "args": {"vendor": "Andina Logistics"}}
    assert "_memory_firewall" not in arguments
    assert captured["argument_lineage"] == {"vendor": ["analysis_signed"]}
    assert "authority" not in captured


def test_hermes_handler_blocks_missing_lineage_without_calling_core(monkeypatch) -> None:
    from memory_firewall.adapters.hermes import pre_tool_call

    monkeypatch.delenv("MEMORY_FIREWALL_UNPROTECTED_TOOLS", raising=False)
    called = False

    def client(_payload):
        nonlocal called
        called = True
        return {"decision": "allow", "reason": ""}

    result = pre_tool_call("pay_invoice", {"vendor": "Andina"}, client=client)

    assert result["action"] == "block"
    assert called is False


def test_hermes_only_bypasses_explicit_unprotected_tools(monkeypatch) -> None:
    from memory_firewall.adapters.hermes import pre_tool_call

    monkeypatch.setenv("MEMORY_FIREWALL_UNPROTECTED_TOOLS", "read_clock")

    assert pre_tool_call("read_clock", {}) == {"action": "modify", "args": {}}
    assert pre_tool_call("READ_CLOCK", {}) == {"action": "modify", "args": {}}
    assert pre_tool_call("unknown_tool", {})["action"] == "block"

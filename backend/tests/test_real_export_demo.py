"""Proof that the demo performs, then prevents, an actual local export."""

from pathlib import Path

from demo_provenance_attack import run_protected, run_vulnerable


def test_vulnerable_mode_creates_real_export(tmp_path: Path) -> None:
    result = run_vulnerable(tmp_path)

    assert result["action_executed"] is True
    assert result["records_leaked"] == 50_000
    assert result["outbound_artifact_created"] is True
    assert Path(result["artifact"]).is_file()


def test_protected_mode_prevents_export_side_effect(tmp_path: Path) -> None:
    result = run_protected(tmp_path)

    assert result["action_executed"] is False
    assert result["records_leaked"] == 0
    assert result["outbound_artifact_created"] is False
    assert result["decision"] == "block"
    assert result["escalation_id"].startswith("esc_")
    assert result["ledger_verified"] is True

"""Regression tests for security audit fixes."""

import time
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from analyzer.detector import analyze_code
from api.main import MAX_TRACKED_IPS, RATE_LIMIT, RATE_WINDOW_SECONDS, _client_ip, _is_rate_limited, _rate_buckets, app

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limit():
    _rate_buckets.clear()
    yield
    _rate_buckets.clear()


def _types(code: str) -> list[str]:
    return [f["type"] for f in analyze_code(code)["findings"]]


# --- Fix 1: NUL bytes sanitized at the core (fail closed) ---


def test_nul_obfuscated_eval_detected_at_core():
    assert "code_injection" in _types("result = ev\x00al(input())")


def test_nul_bytes_do_not_blind_detector_on_other_lines():
    result = analyze_code('print("hello")\x00\neval(input())')
    assert "code_injection" in [f["type"] for f in result["findings"]]


# --- Fix 2: rate limit uses direct connection IP, not X-Forwarded-For ---


def test_client_ip_ignores_x_forwarded_for():
    req = MagicMock()
    req.headers = {"x-forwarded-for": "6.6.6.6, 7.7.7.7"}
    req.client.host = "203.0.113.10"
    assert _client_ip(req) == "203.0.113.10"


def test_rate_limit_not_evaded_by_rotating_xff():
    for i in range(10):
        r = client.post(
            "/api/v1/analyze",
            json={"code": "print('x')"},
            headers={"X-Forwarded-For": f"1.2.3.{i}"},
        )
        assert r.status_code == 200
    r11 = client.post(
        "/api/v1/analyze",
        json={"code": "print('x')"},
        headers={"X-Forwarded-For": "1.2.3.99"},
    )
    assert r11.status_code == 429


# --- Fix 3: path traversal detection preserved after prefilter ---


def test_path_traversal_literal_still_detected():
    assert "path_traversal" in _types('f = open("../../etc/passwd")')


def test_path_traversal_pathjoin_still_detected():
    assert "path_traversal" in _types("p = path.join(base, user_input)")


def test_path_traversal_prefilter_skips_irrelevant_long_line():
    long_line = "open(" + "a" * 50_000 + ")"
    assert _types(long_line) == []


# --- Fix 4: rate buckets bounded (LRU eviction) ---


def test_rate_buckets_bounded():
    for i in range(MAX_TRACKED_IPS + 50):
        _is_rate_limited(f"10.{i // 256}.{i % 256}.1")
    assert len(_rate_buckets) <= MAX_TRACKED_IPS


def test_rate_buckets_lru_evicts_oldest():
    _rate_buckets.clear()
    _is_rate_limited("1.1.1.1")
    for i in range(MAX_TRACKED_IPS):
        _is_rate_limited(f"10.{i // 256}.{i % 256}.2")
    assert "1.1.1.1" not in _rate_buckets


def test_rate_limit_window_expiry():
    _rate_buckets.clear()
    _rate_buckets["9.9.9.9"] = [time.monotonic() - (RATE_WINDOW_SECONDS + 1)] * RATE_LIMIT
    assert _is_rate_limited("9.9.9.9") is False

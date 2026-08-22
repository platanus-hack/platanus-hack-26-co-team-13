import pytest
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limit():
    from api.main import _rate_buckets

    _rate_buckets.clear()
    yield
    _rate_buckets.clear()


def analyze(payload):
    return client.post("/api/v1/analyze", json=payload)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


# TC1: SQL injection via concatenation
def test_tc1_sql_injection():
    r = analyze({"code": 'db.execute("SELECT * FROM users WHERE id = " + user_id)'})
    assert r.status_code == 200
    data = r.json()
    types = [f["type"] for f in data["findings"]]
    assert "sql_injection" in types
    f = next(f for f in data["findings"] if f["type"] == "sql_injection")
    assert f["cwe"] == "CWE-89"
    assert f["severity"] == "high"
    assert f["line"] == 1
    assert data["summary"]["total"] >= 1
    assert data["summary"]["by_severity"].get("high", 0) >= 1
    assert data["summary"]["lines_analyzed"] == 1


# TC3: Hardcoded AWS secret
def test_tc3_hardcoded_secret():
    r = analyze({"code": 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"'})
    assert r.status_code == 200
    types = [f["type"] for f in r.json()["findings"]]
    assert "hardcoded_secret" in types
    f = next(f for f in r.json()["findings"] if f["type"] == "hardcoded_secret")
    assert f["cwe"] == "CWE-798"
    assert f["severity"] == "critical"


# TC4: Command injection
def test_tc4_command_injection():
    r = analyze({"code": 'os.system("ping -c 1 " + host)'})
    assert r.status_code == 200
    types = [f["type"] for f in r.json()["findings"]]
    assert "command_injection" in types
    f = next(f for f in r.json()["findings"] if f["type"] == "command_injection")
    assert f["cwe"] == "CWE-78"
    assert f["severity"] == "critical"


# TC6: Insecure deserialization
def test_tc6_insecure_deserialization():
    r = analyze({"code": "pickle.loads(request.body)"})
    assert r.status_code == 200
    types = [f["type"] for f in r.json()["findings"]]
    assert "insecure_deserialization" in types


# TC7: Code injection via eval
def test_tc7_code_injection():
    r = analyze({"code": "result = eval(user_expression)"})
    assert r.status_code == 200
    types = [f["type"] for f in r.json()["findings"]]
    assert "code_injection" in types


# TC11: Payload > 100KB rejected
def test_tc11_payload_too_large():
    big_code = "x" * 100_001
    r = analyze({"code": big_code})
    assert r.status_code == 422


# Content-Length > 256KB rejected with 413
def test_body_over_256kb_rejected_413():
    huge = "a" * 300_000
    r = client.post(
        "/api/v1/analyze",
        content=huge,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code in (413, 422)


# TC14: Clean parameterized SQL does not produce false positives
def test_tc14_clean_code_no_false_positives():
    r = analyze({"code": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'})
    assert r.status_code == 200
    data = r.json()
    assert data["summary"]["total"] == 0
    assert data["findings"] == []


# Rate limiting: 11 requests -> 429
def test_rate_limiting():
    for _ in range(10):
        r = analyze({"code": "print('hello')"})
        assert r.status_code == 200
    r11 = analyze({"code": "print('hello')"})
    assert r11.status_code == 429


# Empty input -> 422
def test_empty_input_rejected():
    r = analyze({"code": ""})
    assert r.status_code == 422


# Missing field -> 422
def test_missing_field_rejected():
    r = client.post("/api/v1/analyze", json={})
    assert r.status_code == 422


# NUL characters rejected
def test_nul_characters_rejected():
    r = analyze({"code": "print('hi')\x00"})
    assert r.status_code == 422


# Additional detections
def test_xss_detection():
    r = analyze({"code": "element.innerHTML = userInput;"})
    types = [f["type"] for f in r.json()["findings"]]
    assert "xss" in types


def test_path_traversal_detection():
    r = analyze({"code": 'f = open("../../etc/passwd")'})
    types = [f["type"] for f in r.json()["findings"]]
    assert "path_traversal" in types


def test_yaml_unsafe_load_detection():
    r = analyze({"code": "data = yaml.load(stream)"})
    types = [f["type"] for f in r.json()["findings"]]
    assert "insecure_deserialization" in types


def test_yaml_safe_load_no_false_positive():
    r = analyze({"code": "data = yaml.load(stream, Loader=yaml.SafeLoader)"})
    types = [f["type"] for f in r.json()["findings"]]
    assert "insecure_deserialization" not in types


def test_weak_crypto_detection():
    r = analyze({"code": "digest = hashlib.md5(data)"})
    types = [f["type"] for f in r.json()["findings"]]
    assert "weak_crypto" in types


def test_fstring_sql_detection():
    r = analyze({"code": 'query = f"SELECT * FROM users WHERE id = {user_id}"'})
    types = [f["type"] for f in r.json()["findings"]]
    assert "sql_injection" in types


def test_subprocess_shell_true_detection():
    r = analyze({"code": 'subprocess.call(cmd, shell=True)'})
    types = [f["type"] for f in r.json()["findings"]]
    assert "command_injection" in types


# Max findings capped at 100
def test_max_findings_cap():
    lines = "\n".join(f"eval(x_{i})" for i in range(150))
    r = analyze({"code": lines})
    assert r.status_code == 200
    assert r.json()["summary"]["total"] == 100


# Output format shape
def test_output_format():
    r = analyze({"code": 'os.system("ls " + path)'})
    data = r.json()
    assert set(data.keys()) == {"findings", "summary"}
    assert set(data["summary"].keys()) == {"total", "by_severity", "lines_analyzed"}
    finding = data["findings"][0]
    assert set(finding.keys()) == {"type", "cwe", "severity", "line", "description", "snippet"}


# Multi-line: correct line numbers
def test_line_numbers():
    code = "x = 1\ny = 2\nos.system('rm -rf ' + path)\n"
    r = analyze({"code": code})
    f = next(f for f in r.json()["findings"] if f["type"] == "command_injection")
    assert f["line"] == 3

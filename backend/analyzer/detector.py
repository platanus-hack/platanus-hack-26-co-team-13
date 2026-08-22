"""Deterministic, line-by-line code analysis. Never executes the input."""

from dataclasses import dataclass

from .patterns import PATTERNS

MAX_FINDINGS = 100


@dataclass(frozen=True)
class Finding:
    type: str
    cwe: str
    severity: str
    line: int
    description: str
    snippet: str

    def as_dict(self) -> dict:
        return {
            "type": self.type,
            "cwe": self.cwe,
            "severity": self.severity,
            "line": self.line,
            "description": self.description,
            "snippet": self.snippet,
        }


def analyze_code(code: str) -> dict:
    """Analyze code purely with regex, line by line. No execution, ever."""
    if "\x00" in code:
        # Fail closed at the core: NUL bytes can obfuscate identifiers
        # (e.g. "ev\x00al") to bypass detection. Strip them BEFORE analysis
        # so the obfuscated form is still detected, regardless of what the
        # HTTP edge already validates.
        code = code.replace("\x00", "")
    lines = code.split("\n")
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rule in PATTERNS:
            prefilter = rule.get("prefilter")
            if prefilter is not None:
                lower = raw_line.lower()
                if not any(p in lower for p in prefilter):
                    continue
            if rule["pattern"].search(raw_line):
                key = (rule["type"], line_number)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        type=rule["type"],
                        cwe=rule["cwe"],
                        severity=rule["severity"],
                        line=line_number,
                        description=rule["description"],
                        snippet=stripped[:200],
                    )
                )
                if len(findings) >= MAX_FINDINGS:
                    return _build_response(findings, len(lines))

    return _build_response(findings, len(lines))


def _build_response(findings: list[Finding], lines_analyzed: int) -> dict:
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "findings": [f.as_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
            "lines_analyzed": lines_analyzed,
        },
    }

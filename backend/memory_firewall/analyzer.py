"""Deterministic analysis for persistent-memory security threats.

This module deliberately does not ask an LLM to decide whether content is safe.
Rules provide explainable signals; policy decides what the content may do.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .schemas import Severity


@dataclass(frozen=True)
class MemoryRule:
    type: str
    severity: Severity
    confidence: float
    description: str
    indicator: str
    pattern: re.Pattern[str]


# Patterns are intentionally bounded and line-oriented. The endpoint has a
# fixed input limit, and no pattern uses nested overlapping quantifiers.
RULES: tuple[MemoryRule, ...] = (
    MemoryRule(
        type="prompt_injection",
        severity=Severity.HIGH,
        confidence=0.98,
        description="Attempts to override instructions that should control the agent.",
        indicator="instruction override language",
        pattern=re.compile(
            r"\b(?:ignore|disregard|forget|override)\b\s+(?:all\s+)?"
            r"(?:the\s+)?(?:previous|prior|above|system|developer)\s+"
            r"(?:instructions?|prompt|rules?)\b",
            re.IGNORECASE,
        ),
    ),
    MemoryRule(
        type="system_instruction_override",
        severity=Severity.HIGH,
        confidence=0.97,
        description="Attempts to access, reveal, or replace system/developer instructions.",
        indicator="system or developer instruction access",
        pattern=re.compile(
            r"\b(?:reveal|show|print|provide|leak|dump|disclose|replace|change)\b"
            r"[^\n]{0,120}\b(?:system|developer)\s+"
            r"(?:prompt|instructions?|message)\b",
            re.IGNORECASE,
        ),
    ),
    MemoryRule(
        type="persistent_prompt_injection",
        severity=Severity.HIGH,
        confidence=0.98,
        description="Attempts to persist an instruction for future sessions or users.",
        indicator="request to persist agent instructions",
        pattern=re.compile(
            r"\b(?:store|save|remember|persist|write|add)\b[^\n]{0,120}\b"
            r"(?:permanently|forever|for\s+future\s+sessions?|in\s+memory|to\s+memory|"
            r"as\s+(?:a\s+)?(?:rule|instruction|policy))\b",
            re.IGNORECASE,
        ),
    ),
    MemoryRule(
        type="secret_exfiltration",
        severity=Severity.CRITICAL,
        confidence=0.98,
        description="Attempts to disclose, export, or send secrets or internal context.",
        indicator="request to disclose secret or internal context",
        pattern=re.compile(
            r"\b(?:reveal|send|export|dump|forward|share|leak|post|print)\b"
            r"[^\n]{0,140}\b(?:api[ _-]?key|secret|token|password|credential|"
            r"environment\s+variables?|system\s+prompt|internal\s+context)\b",
            re.IGNORECASE,
        ),
    ),
    MemoryRule(
        type="memory_manipulation",
        severity=Severity.HIGH,
        confidence=0.94,
        description="Attempts to delete, overwrite, alter, or relabel agent memory.",
        indicator="memory mutation or trust relabeling request",
        pattern=re.compile(
            r"\b(?:delete|erase|forget|overwrite|modify|change|clear|reset|mark)\b"
            r"[^\n]{0,100}\b(?:memory|memories|context|instructions?|trusted|verified|safe)\b",
            re.IGNORECASE,
        ),
    ),
    MemoryRule(
        type="future_behavior_modification",
        severity=Severity.HIGH,
        confidence=0.93,
        description="Attempts to alter the agent's behavior in future interactions.",
        indicator="future behavior instruction",
        pattern=re.compile(
            r"\b(?:from\s+now\s+on|in\s+future\s+sessions?|for\s+all\s+future|"
            r"always)\b[^\n]{0,140}\b(?:do|ignore|use|remember|send|reveal|allow|"
            r"treat|follow)\b",
            re.IGNORECASE,
        ),
    ),
    MemoryRule(
        type="jailbreak_instruction",
        severity=Severity.MEDIUM,
        confidence=0.90,
        description="Contains language commonly used to disable safety controls.",
        indicator="jailbreak or safeguard bypass language",
        pattern=re.compile(
            r"\b(?:jailbreak|developer\s+mode|DAN|no\s+restrictions?|"
            r"bypass\s+(?:safety|safeguards?)|disable\s+safeguards?)\b",
            re.IGNORECASE,
        ),
    ),
    MemoryRule(
        type="sensitive_information",
        severity=Severity.MEDIUM,
        confidence=0.88,
        description="Contains an indicator of regulated or highly sensitive information.",
        indicator="sensitive information label",
        pattern=re.compile(
            r"\b(?:SSN|social\s+security|credit\s+card|passport|national\s+ID|"
            r"bank\s+account|date\s+of\s+birth|medical\s+record|health\s+record)\b",
            re.IGNORECASE,
        ),
    ),
)


_SECRET_RE = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk_live_[A-Za-z0-9]+)\b"
    r"|-----BEGIN[A-Z ]*PRIVATE KEY-----"
    r"|\b(?:password|passwd|secret|api[ _-]?key|apikey|token)\s*[:=]\s*"
    r"[\"'][^\"'\n]{6,}[\"']",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")


def normalize_memory_content(content: str) -> str:
    """Normalize unicode and reject controls before analysis.

    Rejecting NUL in the core prevents callers that bypass HTTP validation from
    getting a different security result than API callers.
    """

    normalized = unicodedata.normalize("NFKC", content)
    for character in normalized:
        codepoint = ord(character)
        if codepoint == 0 or (codepoint < 32 and character not in "\n\r\t"):
            raise ValueError("content contains unsupported control characters")
    return normalized


def sanitize_content(content: str) -> str:
    """Remove common secrets and email addresses before persistence/response."""

    redacted = _SECRET_RE.sub("[REDACTED_SECRET]", content)
    return _EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)


def analyze_memory(content: str) -> tuple[list[dict[str, object]], float, str]:
    """Return threats, deterministic risk score, and safe content.

    The returned indicator is a static rule description rather than a matched
    substring, so the API does not echo sensitive attacker-controlled content.
    """

    normalized = normalize_memory_content(content)
    findings: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()

    for line_number, line in enumerate(normalized.splitlines() or [normalized], start=1):
        if not line.strip():
            continue
        for rule in RULES:
            if not rule.pattern.search(line):
                continue
            key = (rule.type, line_number)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "type": rule.type,
                    "severity": rule.severity,
                    "line": line_number,
                    "description": rule.description,
                    "confidence": rule.confidence,
                    "indicator": rule.indicator,
                }
            )

    severity_weight = {
        Severity.CRITICAL: 0.98,
        Severity.HIGH: 0.84,
        Severity.MEDIUM: 0.58,
        Severity.LOW: 0.25,
    }
    if not findings:
        risk_score = 0.0
    else:
        maximum = max(severity_weight[item["severity"]] for item in findings)
        risk_score = min(1.0, maximum + max(0, len(findings) - 1) * 0.03)

    return findings, round(risk_score, 2), sanitize_content(normalized)

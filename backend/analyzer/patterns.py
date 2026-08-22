"""Compiled regex patterns for deterministic vulnerability detection.

Security notes:
- All patterns are compiled once at import time (module-level).
- Patterns are linear: no nested/overlapping quantifiers (ReDoS-safe).
- Rules may declare a "prefilter" tuple: the regex is only applied to lines
  that contain at least one of those literal substrings. This keeps
  backtracking-prone patterns (e.g. path traversal) off long irrelevant lines.
"""

import re

# Each rule: (type, cwe, severity, description, compiled_pattern)
# All patterns operate on a single line of code.

PATTERNS: list[dict] = [
    # --- SQL Injection (CWE-89) ---
    {
        "type": "sql_injection",
        "cwe": "CWE-89",
        "severity": "high",
        "pattern": re.compile(
            r"(?:execute|executemany|executescript)\s*\(\s*[\"'][^\"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)[^\"']*[\"']\s*(?:\+|%|\.format|f\"|f')"
            r"|\+\s*\w+\s*\)\s*$"
            r"|f[\"'][^\"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^\"']*",
            re.IGNORECASE,
        ),
        "description": "Possible SQL injection via string concatenation or interpolation in execute() call",
    },
    # --- XSS (CWE-79) ---
    {
        "type": "xss",
        "cwe": "CWE-79",
        "severity": "high",
        "pattern": re.compile(
            r"innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|\.html\s*\(",
            re.IGNORECASE,
        ),
        "description": "Possible XSS via unsafe DOM/HTML assignment",
    },
    # --- Hardcoded secrets (CWE-798) ---
    {
        "type": "hardcoded_secret",
        "cwe": "CWE-798",
        "severity": "critical",
        "pattern": re.compile(
            r"AKIA[0-9A-Z]{16}"
            r"|ghp_[A-Za-z0-9]{36}"
            r"|sk_live_[A-Za-z0-9]+"
            r"|-----BEGIN[A-Z ]*PRIVATE KEY"
            r"|(?:password|passwd|secret|api_key|apikey|token)\s*=\s*[\"'][^\"'\s]{6,}[\"']",
            re.IGNORECASE,
        ),
        "description": "Hardcoded secret or credential detected",
    },
    # --- Command Injection (CWE-78) ---
    {
        "type": "command_injection",
        "cwe": "CWE-78",
        "severity": "critical",
        "pattern": re.compile(
            r"os\.system\s*\("
            r"|os\.popen\s*\("
            r"|subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
            re.IGNORECASE,
        ),
        "description": "Possible command injection via shell command execution",
    },
    # --- Path Traversal (CWE-22) ---
    # Prefiltered: only applied to lines that literally contain a
    # parent-directory segment ("../" or "..\\"). Quantifiers are bounded
    # so scanning stays linear even on long lines.
    {
        "type": "path_traversal",
        "cwe": "CWE-22",
        "severity": "high",
        "prefilter": ("../", "..\\"),
        "pattern": re.compile(
            r"open\s*\(\s*[\"'][^\"']{0,200}\.\./"
            r"|open\s*\([^)]{0,200}\.\./"
            r"|\.\./\.\./",
            re.IGNORECASE,
        ),
        "description": "Possible path traversal via relative path manipulation",
    },
    # Prefiltered: only applied to lines mentioning path.join; bounded scan.
    {
        "type": "path_traversal",
        "cwe": "CWE-22",
        "severity": "high",
        "prefilter": ("path.join",),
        "pattern": re.compile(
            r"path\.join\s*\([^)]{0,200}(?:user_input|request|input|filename|user)",
            re.IGNORECASE,
        ),
        "description": "Possible path traversal via untrusted input in path.join()",
    },
    # --- Insecure Deserialization (CWE-502) ---
    {
        "type": "insecure_deserialization",
        "cwe": "CWE-502",
        "severity": "critical",
        "pattern": re.compile(
            r"pickle\.loads?\s*\("
            r"|cPickle\.loads?\s*\("
            r"|yaml\.load\s*\((?![^)]*SafeLoader)"
            r"|marshal\.loads\s*\("
            r"|dill\.loads\s*\(",
            re.IGNORECASE,
        ),
        "description": "Insecure deserialization of untrusted data",
    },
    # --- Code Injection (CWE-95) ---
    {
        "type": "code_injection",
        "cwe": "CWE-95",
        "severity": "critical",
        "pattern": re.compile(
            r"(?<![\w.])eval\s*\("
            r"|(?<![\w.])exec\s*\("
            r"|new\s+Function\s*\("
            r"|window\.eval\s*\(",
            re.IGNORECASE,
        ),
        "description": "Possible code injection via dynamic code execution",
    },
    # --- Weak Crypto (CWE-327) ---
    {
        "type": "weak_crypto",
        "cwe": "CWE-327",
        "severity": "medium",
        "pattern": re.compile(
            r"hashlib\.md5\s*\("
            r"|hashlib\.sha1\s*\("
            r"|Crypto\.Hash\.MD5"
            r"|Crypto\.Hash\.SHA"
            r"|Math\.random\s*\(\s*\)[^;]*(?:token|password|secret|key|id)"
            r"|(?:token|password|secret|key)[^;=\n]*=\s*[^;\n]*Math\.random",
            re.IGNORECASE,
        ),
        "description": "Use of weak cryptographic primitive (MD5/SHA1/Math.random for secrets)",
    },
]

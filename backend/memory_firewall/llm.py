"""Minimal OpenAI-compatible client for a hosted chat model.

Defaults target NVIDIA's build.nvidia.com gateway, which serves the Nemotron
family behind an OpenAI-compatible surface. Any provider speaking that protocol
works by overriding the base URL and model.

The firewall treats this transport as untrusted and unreliable infrastructure:
every failure mode collapses into :class:`LLMUnavailable` so that callers make
their own fail-closed decision instead of receiving a silent default.

Note for operators: NVIDIA's free trial endpoints log requests and are not
intended for confidential data. Keep the demo on synthetic fixtures.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
# Chosen by measurement, not by size. The larger reasoning variants narrate for
# longer than the request budget allows and return an empty content field; this
# one answers with parseable JSON in roughly 2-3 seconds.
DEFAULT_MODEL = "nvidia/nemotron-3-nano-30b-a3b"
DEFAULT_TIMEOUT_SECONDS = 12.0
_MAX_RESPONSE_BYTES = 64_000

API_KEY_ENV = "MEMORY_FIREWALL_LLM_API_KEY"
MODEL_ENV = "MEMORY_FIREWALL_LLM_MODEL"
BASE_URL_ENV = "MEMORY_FIREWALL_LLM_BASE_URL"
TIMEOUT_ENV = "MEMORY_FIREWALL_LLM_TIMEOUT"


class LLMUnavailable(RuntimeError):
    """The model could not be reached or returned an unusable response."""


@dataclass(frozen=True)
class LLMConfig:
    api_key: str
    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS


def load_config() -> LLMConfig | None:
    """Build a config from the environment, or ``None`` when unconfigured.

    Returning ``None`` rather than raising lets the caller distinguish "no
    semantic layer installed" from "the semantic layer failed", which are two
    different security postures.
    """

    api_key = os.getenv(API_KEY_ENV, "").strip()
    if not api_key:
        return None
    try:
        timeout = float(os.getenv(TIMEOUT_ENV, DEFAULT_TIMEOUT_SECONDS))
    except ValueError:
        timeout = DEFAULT_TIMEOUT_SECONDS
    return LLMConfig(
        api_key=api_key,
        model=os.getenv(MODEL_ENV, DEFAULT_MODEL).strip() or DEFAULT_MODEL,
        base_url=os.getenv(BASE_URL_ENV, DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL,
        timeout_seconds=timeout,
    )


def is_configured() -> bool:
    """Report whether a semantic verification backend is available."""

    return load_config() is not None


def complete(
    *,
    system_prompt: str,
    user_prompt: str,
    config: LLMConfig,
    max_tokens: int = 400,
    temperature: float = 0.0,
) -> str:
    """Run one chat completion and return the raw assistant text.

    Raises :class:`LLMUnavailable` on any transport, protocol, or shape error.
    """

    body = json.dumps(
        {
            "model": config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        config.base_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:  # noqa: S310 - fixed gateway
            if response.status < 200 or response.status >= 300:
                raise LLMUnavailable(f"gateway returned HTTP {response.status}")
            raw = response.read(_MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:  # pragma: no cover - network dependent
        raise LLMUnavailable(f"gateway returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LLMUnavailable(f"gateway unreachable: {exc}") from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
        choices = payload["choices"]
        if not choices:
            raise LLMUnavailable("gateway returned no choices")
        content = choices[0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError, UnicodeDecodeError) as exc:
        raise LLMUnavailable(f"gateway returned an unreadable body: {exc}") from exc

    if not isinstance(content, str) or not content.strip():
        raise LLMUnavailable("gateway returned empty content")
    return content

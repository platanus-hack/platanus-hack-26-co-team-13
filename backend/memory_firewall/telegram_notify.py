"""Operator notifications for gated actions, over the Telegram Bot API.

Deliberately dependency-free: this speaks the HTTPS API directly with urllib,
the same way `llm.py` reaches the model gateway. The `python-telegram-bot` SDK
is not a backend dependency -- the production image installs only what
`pyproject.toml` declares -- so anything that imports it is dead code in the
deployed container. Adding it would also drag a second HTTP stack into the
image for what amounts to one JSON POST.

Two rules govern this module:

1. Notification is best-effort and never influences a decision. The firewall
   has already decided by the time we get here; an unreachable chat is not a
   reason to change that, so every failure is logged and swallowed.
2. The alert text is treated as hostile. Message bodies reach us from
   attacker-controlled email, so the payload is sent as plain text with no
   parse mode. Markdown would let injected content forge formatting, spoof
   fields, or break the message apart.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_API_BASE = "https://api.telegram.org"
_DEFAULT_TIMEOUT_SECONDS = 5
# Telegram rejects messages over 4096 characters. Stay well under it so a long
# quoted email cannot silently drop the verdict printed at the top.
_MAX_MESSAGE_CHARS = 3_500
_MAX_FIELD_CHARS = 400


@dataclass(frozen=True)
class TelegramConfig:
    """Everything needed to reach one operator chat."""

    token: str
    chat_id: str
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


def load_config() -> TelegramConfig | None:
    """Read configuration from the environment, or None when unconfigured.

    Absence is a supported state: the firewall runs exactly as before and
    simply does not narrate itself to an operator.
    """

    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_ADMIN_CHAT_ID", "").strip()
    if not token or not chat_id:
        return None

    raw_timeout = os.getenv("TELEGRAM_TIMEOUT", "").strip()
    try:
        timeout = int(raw_timeout) if raw_timeout else _DEFAULT_TIMEOUT_SECONDS
    except ValueError:
        timeout = _DEFAULT_TIMEOUT_SECONDS
    if timeout < 1 or timeout > 30:
        timeout = _DEFAULT_TIMEOUT_SECONDS

    return TelegramConfig(token=token, chat_id=chat_id, timeout_seconds=timeout)


def is_configured() -> bool:
    """True when an operator chat is reachable in principle."""

    return load_config() is not None


def _clip(value: object, limit: int = _MAX_FIELD_CHARS) -> str:
    """Bound one field so a hostile body cannot crowd out the verdict."""

    text = str(value if value is not None else "-").strip() or "-"
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def send_message(text: str, config: TelegramConfig | None = None) -> bool:
    """Post one plain-text message. Returns True only on a confirmed send."""

    config = config or load_config()
    if config is None:
        return False

    body = json.dumps(
        {
            "chat_id": config.chat_id,
            "text": text[:_MAX_MESSAGE_CHARS],
            # No parse_mode on purpose: the payload quotes untrusted content.
            "disable_web_page_preview": True,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        f"{_API_BASE}/bot{config.token}/sendMessage",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(  # noqa: S310 - fixed, non-user-controlled host
            request, timeout=config.timeout_seconds
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # pragma: no cover - network dependent
        detail = ""
        try:
            detail = exc.read().decode("utf-8")[:200]
        except Exception:  # noqa: BLE001 - diagnostics only
            pass
        logger.warning("Telegram rejected the alert (%s): %s", exc.code, detail)
        return False
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning("Telegram unreachable: %s", exc)
        return False
    except ValueError as exc:  # malformed JSON
        logger.warning("Telegram returned an unreadable reply: %s", exc)
        return False

    if not payload.get("ok"):
        logger.warning("Telegram reported failure: %s", payload.get("description"))
        return False
    return True


def notify_gated_action(
    *,
    action: str,
    decision: str,
    reason: str,
    required_authority: str,
    provided_authority: str,
    question: str,
    message_id: str,
    risk_score: float | None = None,
    threats: list[str] | None = None,
    semantic_judgement: str | None = None,
    semantic_reason: str | None = None,
) -> bool:
    """Tell the operator that an action was held or refused, and why.

    Never raises: notification failure must not surface as a request failure,
    because the security outcome is already settled and recorded in the ledger.
    """

    try:
        config = load_config()
        if config is None:
            return False

        headline = {
            "block": "BLOQUEADA",
            "review": "RETENIDA PARA REVISION",
        }.get(decision.lower(), decision.upper())

        lines = [
            f"[FIREWALL] Accion {headline}",
            "",
            f"Accion solicitada : {_clip(action, 64)}",
            f"Decision          : {_clip(decision, 32)}",
            f"Autoridad exigida : {_clip(required_authority, 32)}",
            f"Autoridad del dato: {_clip(provided_authority, 32)}",
        ]

        if risk_score is not None:
            lines.append(f"Puntaje de riesgo : {round(float(risk_score) * 100)}%")

        if threats:
            lines.append(f"Patrones          : {_clip(', '.join(threats), 200)}")

        if semantic_judgement:
            lines.append(f"Juicio semantico  : {_clip(semantic_judgement, 32)}")
            if semantic_reason:
                lines.append(f"Motivo semantico  : {_clip(semantic_reason, 300)}")

        lines += [
            "",
            f"Motivo: {_clip(reason)}",
            "",
            f"Pregunta al agente: {_clip(question, 300)}",
            f"Memoria: {_clip(message_id, 64)}",
        ]

        return send_message("\n".join(lines), config)
    except Exception:  # noqa: BLE001 - notification must never break a request
        logger.exception("Failed to deliver the Telegram alert")
        return False

"""AI analysis layer.

Five callable operations:
  * classify_service     — assign a category (database, web, iot, etc.)
  * categorize_exposure  — bucket a host into intent/risk categories
  * prioritize_risks     — re-rank the deterministic risk_scorer output
  * detect_anomaly       — compare current snapshot to historical norm
  * summarize_host       — human-readable summary for the UI

Each function gracefully degrades to a no-op when AI is disabled or
credentials are missing. The deterministic risk_scorer is always the
authoritative score; the AI layer adds context only.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from app.config import settings

log = structlog.get_logger(__name__)


SYSTEM_PROMPT = """You are NeuroScanIQ's defensive cybersecurity analyst.
You ONLY analyze publicly observable infrastructure data already collected by
NeuroScanIQ scanners. You NEVER:
  * suggest how to exploit a host,
  * produce attack payloads, scripts, or commands,
  * write code that would harm a system,
  * speculate about credentials, secrets, or undisclosed vulnerabilities.

Output is JSON conforming to the schema given by the user.
Be concise, factual, and label uncertainty explicitly."""


async def _anthropic_call(user_prompt: str, *, max_tokens: int = 600) -> dict[str, Any] | None:
    if not settings.ai_enabled or not settings.anthropic_api_key:
        return None
    try:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        msg = await client.messages.create(
            model=settings.ai_model_classifier,
            max_tokens=max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = "".join(block.text for block in msg.content if block.type == "text")
        return json.loads(_strip_fences(text))
    except Exception as e:
        log.warning("ai_call_failed", error=str(e))
        return None


def _strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
    return text.strip()


# ---------- Public API ----------
async def classify_service(banner: str, port: int, server_header: str | None = None) -> str | None:
    """Return a single category string for a service."""
    payload = {"banner": banner[:1500], "port": port, "server": server_header or ""}
    prompt = (
        "Classify this service into ONE of: "
        "web_server, database, message_queue, iot_device, industrial_control, "
        "remote_admin, vpn, mail_server, dns_server, cache, monitoring, unknown.\n\n"
        f"Input:\n{json.dumps(payload)}\n\n"
        'Return JSON: {"category": "..."}'
    )
    result = await _anthropic_call(prompt, max_tokens=80)
    return result.get("category") if result else None


async def categorize_exposure(host_snapshot: dict[str, Any]) -> dict[str, Any]:
    """Return tags describing exposure posture."""
    prompt = (
        "Analyze this host snapshot and return categorical tags. Do not include "
        "any exploitation guidance.\n\n"
        f"Snapshot:\n{json.dumps(host_snapshot)[:4000]}\n\n"
        'Return JSON: {"tags": ["..."], "summary": "one sentence"}'
    )
    result = await _anthropic_call(prompt, max_tokens=300)
    return result or {"tags": [], "summary": ""}


async def prioritize_risks(deterministic_factors: dict[str, Any]) -> list[str]:
    """Take deterministic risk factors and return a prioritized list."""
    if not deterministic_factors:
        return []
    prompt = (
        "Given these risk factors, return them ranked by operational urgency "
        "for the asset owner. Do NOT add new factors.\n\n"
        f"Factors:\n{json.dumps(deterministic_factors)}\n\n"
        'Return JSON: {"ordered": ["factor_name_1", "factor_name_2", ...]}'
    )
    result = await _anthropic_call(prompt, max_tokens=200)
    return result.get("ordered", list(deterministic_factors.keys())) if result else list(deterministic_factors.keys())


async def detect_anomaly(current: dict[str, Any], history: list[dict[str, Any]]) -> dict[str, Any]:
    """Diff current snapshot against recent history and surface anomalies."""
    prompt = (
        "Compare the current host snapshot to its recent observations. "
        "Report meaningful changes only.\n\n"
        f"Current:\n{json.dumps(current)[:2500]}\n\n"
        f"History (most recent first, up to 5):\n{json.dumps(history[:5])[:3500]}\n\n"
        'Return JSON: {"anomalies": [{"signal": "...", "severity": "low|medium|high|critical", "detail": "..."}]}'
    )
    result = await _anthropic_call(prompt, max_tokens=500)
    return result or {"anomalies": []}


async def summarize_host(host_snapshot: dict[str, Any]) -> str:
    """One-paragraph human-readable summary for the host detail page."""
    prompt = (
        "Write a 2-3 sentence operational summary for an SOC analyst about "
        "this host. Focus on what is exposed, where it is hosted, and the "
        "headline risks. No exploitation guidance.\n\n"
        f"Host:\n{json.dumps(host_snapshot)[:4000]}\n\n"
        'Return JSON: {"summary": "..."}'
    )
    result = await _anthropic_call(prompt, max_tokens=300)
    return (result or {}).get("summary", "")

"""Transactional email.

Wraps `emails` for SMTP delivery with Jinja-rendered templates. In tests
we patch this whole module.
"""

from __future__ import annotations

from typing import Any

import emails
import structlog
from jinja2 import Environment, select_autoescape

from app.config import settings

log = structlog.get_logger(__name__)

_jinja = Environment(autoescape=select_autoescape(["html", "xml"]))


_TEMPLATES = {
    "verify_email": (
        "Verify your NeuroScanIQ account",
        "Welcome to NeuroScanIQ. Confirm your email: {{ link }}",
    ),
    "password_reset": (
        "Reset your NeuroScanIQ password",
        "Reset link (valid for 24h): {{ link }}",
    ),
    "alert": (
        "[NeuroScanIQ {{ severity|upper }}] {{ title }}",
        "{{ description }}\n\nView in dashboard: {{ link }}",
    ),
    "monitor_verified": (
        "Your NeuroScanIQ monitor is active",
        "Asset {{ asset }} is verified and now being monitored.",
    ),
}


async def send(template: str, *, to: str, context: dict[str, Any]) -> bool:
    if template not in _TEMPLATES:
        log.error("unknown_email_template", template=template)
        return False

    subj_tpl, body_tpl = _TEMPLATES[template]
    subject = _jinja.from_string(subj_tpl).render(**context)
    body = _jinja.from_string(body_tpl).render(**context)

    if not settings.smtp_host:
        log.info("email_skipped_no_smtp", template=template, to=to, subject=subject)
        return False

    message = emails.Message(
        subject=subject,
        text=body,
        mail_from=settings.smtp_from,
    )
    smtp = {
        "host": settings.smtp_host,
        "port": settings.smtp_port,
        "user": settings.smtp_user,
        "password": settings.smtp_password,
        "tls": True,
    }
    response = message.send(to=to, smtp=smtp)
    ok = response.status_code in (250, 200)
    log.info("email_sent", template=template, to=to, ok=ok)
    return ok

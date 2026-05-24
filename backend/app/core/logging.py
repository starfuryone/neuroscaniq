"""Structured logging via structlog.

Production emits JSON; development uses a colorized console renderer.
"""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(env: str) -> None:
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.INFO if env != "development" else logging.DEBUG,
    )

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if env == "development":
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer(colors=True)
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Quieten noisy libraries
    for noisy in ("uvicorn.access", "boto3", "botocore", "urllib3", "opensearch"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

"""FastAPI application factory.

Wires together middleware, routers, lifespan hooks, and observability.
This module is intentionally thin — feature logic lives in `app.api.*`,
`app.services.*`, and `app.workers.*`.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.gzip import GZipMiddleware

from app.api import (
    admin,
    alerts,
    api_keys,
    auth,
    billing,
    health,
    hosts,
    monitor,
    screenshots,
    search,
    users,
)
from app.config import settings
from app.core.errors import APIError, register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import (
    AuditLogMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from app.db.session import engine
from app.services.opensearch import opensearch_client
from app.services.redis import redis_client

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup / shutdown hooks for the API process."""
    configure_logging(settings.app_env)
    log.info("startup", env=settings.app_env, version="0.1.0")

    # Sanity-check critical secrets in production.
    if settings.app_env == "production":
        if settings.jwt_secret.startswith("change-me"):
            raise RuntimeError("JWT_SECRET must be set in production")

    # Warm pooled clients so first requests aren't slow.
    await redis_client.ping()
    await opensearch_client.ensure_indices()

    yield

    log.info("shutdown")
    await redis_client.aclose()
    await opensearch_client.close()
    await engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="NeuroScanIQ API",
        description=(
            "AI-Powered Internet Exposure Intelligence. "
            "Defensive cybersecurity and authorized asset monitoring only."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ---------- Middleware (outermost first) ----------
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuditLogMiddleware)
    app.add_middleware(RateLimitMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-RateLimit-Remaining", "X-Request-Id"],
        max_age=600,
    )

    if settings.app_env == "production":
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=[
                # Override via deployment; placeholder for safety
                "neuroscaniq.io",
                "api.neuroscaniq.io",
                "*.neuroscaniq.io",
            ],
        )

    # ---------- Exception handlers ----------
    register_exception_handlers(app)

    # ---------- Routers ----------
    api_v1 = "/api/v1"
    app.include_router(health.router, tags=["health"])
    app.include_router(auth.router, prefix=f"{api_v1}/auth", tags=["auth"])
    app.include_router(users.router, prefix=f"{api_v1}/users", tags=["users"])
    app.include_router(api_keys.router, prefix=f"{api_v1}/api-keys", tags=["api-keys"])
    app.include_router(search.router, prefix=f"{api_v1}/search", tags=["search"])
    app.include_router(hosts.router, prefix=f"{api_v1}/host", tags=["hosts"])
    app.include_router(monitor.router, prefix=f"{api_v1}/monitor", tags=["monitor"])
    app.include_router(alerts.router, prefix=f"{api_v1}/alerts", tags=["alerts"])
    app.include_router(screenshots.router, prefix=f"{api_v1}/screenshots", tags=["screenshots"])
    app.include_router(billing.router, prefix=f"{api_v1}/billing", tags=["billing"])
    app.include_router(admin.router, prefix=f"{api_v1}/admin", tags=["admin"])

    return app


app = create_app()

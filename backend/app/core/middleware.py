"""ASGI middleware: security headers, rate limiting, audit logging."""

from __future__ import annotations

import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.config import settings
from app.core.security import extract_prefix
from app.services.redis import redis_client

log = structlog.get_logger(__name__)


# ---------- Security headers ----------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply hardening headers to every response."""

    CSP = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "connect-src 'self' https://api.stripe.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "strict-origin-when-cross-origin"
        h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if settings.app_env == "production":
            h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
            h["Content-Security-Policy"] = self.CSP
        h.setdefault("X-Request-Id", getattr(request.state, "request_id", ""))
        return response


# ---------- Audit / request tracing ----------
class AuditLogMiddleware(BaseHTTPMiddleware):
    """Assign a request id, time the request, and log structured access lines."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.perf_counter()

        structlog.contextvars.bind_contextvars(request_id=request_id)

        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.perf_counter() - start) * 1000
            log.exception(
                "request_failed",
                method=request.method,
                path=request.url.path,
                duration_ms=round(duration_ms, 2),
            )
            structlog.contextvars.clear_contextvars()
            raise

        duration_ms = (time.perf_counter() - start) * 1000
        log.info(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=round(duration_ms, 2),
            user_id=getattr(request.state, "user_id", None),
        )
        response.headers["X-Request-Id"] = request_id
        structlog.contextvars.clear_contextvars()
        return response


# ---------- Rate limiting ----------
class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter keyed by API key prefix, JWT subject, or IP.

    Implemented with a Redis sorted set: each request inserts `(now, uuid)`
    with a TTL of 60s. We then count elements within the 60s window.
    """

    WINDOW_SECONDS = 60

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Skip health endpoints and docs
        if request.url.path.startswith(("/healthz", "/docs", "/redoc", "/openapi.json")):
            return await call_next(request)

        identity, plan_limit = self._identify(request)

        try:
            allowed, remaining, reset_in = await self._check(identity, plan_limit)
        except Exception:  # Redis down -> fail open but log
            log.warning("rate_limit_check_failed", identity=identity)
            return await call_next(request)

        if not allowed:
            return Response(
                content='{"error":{"code":"rate_limited","message":"Too many requests"}}',
                status_code=429,
                media_type="application/json",
                headers={
                    "Retry-After": str(reset_in),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Limit": str(plan_limit),
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(plan_limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response

    def _identify(self, request: Request) -> tuple[str, int]:
        api_key = request.headers.get("X-API-Key")
        if api_key:
            prefix = extract_prefix(api_key) or "invalid"
            # Conservative default; api_keys router may override per-key.
            return f"apikey:{prefix}", settings.rate_limit_pro_per_minute

        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return f"jwt:{auth[7:][:32]}", settings.rate_limit_pro_per_minute

        ip = request.client.host if request.client else "anon"
        return f"ip:{ip}", settings.rate_limit_free_per_minute

    async def _check(self, identity: str, limit: int) -> tuple[bool, int, int]:
        key = f"rl:{identity}"
        now_ms = int(time.time() * 1000)
        window_start = now_ms - self.WINDOW_SECONDS * 1000
        member = f"{now_ms}-{uuid.uuid4().hex[:8]}"

        pipe = redis_client.client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zadd(key, {member: now_ms})
        pipe.zcard(key)
        pipe.expire(key, self.WINDOW_SECONDS)
        _, _, count, _ = await pipe.execute()

        if count > limit:
            return False, 0, self.WINDOW_SECONDS

        return True, max(0, limit - count), self.WINDOW_SECONDS

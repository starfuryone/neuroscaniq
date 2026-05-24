"""Typed application errors and JSON error envelope."""

from __future__ import annotations

import structlog
from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError, NoResultFound

log = structlog.get_logger(__name__)


class APIError(Exception):
    """Base class for application errors that translate to JSON responses."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "bad_request"

    def __init__(self, message: str, *, code: str | None = None, status_code: int | None = None, details: dict | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code
        self.details = details or {}


class NotFound(APIError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"


class Unauthorized(APIError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unauthorized"


class Forbidden(APIError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"


class Conflict(APIError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


class RateLimited(APIError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"


class OwnershipRequired(APIError):
    """Raised when an action needs ownership proof and none exists."""

    status_code = status.HTTP_412_PRECONDITION_FAILED
    code = "ownership_required"


class ScanTargetRejected(APIError):
    """Raised when a scan target falls outside permitted CIDRs."""

    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    code = "target_rejected"


def _envelope(*, code: str, message: str, status_code: int, request_id: str | None = None, details: dict | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": details or {},
                "request_id": request_id,
            }
        },
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Attach exception handlers that emit the consistent error envelope."""

    @app.exception_handler(APIError)
    async def handle_api_error(request: Request, exc: APIError) -> JSONResponse:
        return _envelope(
            code=exc.code,
            message=exc.message,
            status_code=exc.status_code,
            request_id=getattr(request.state, "request_id", None),
            details=exc.details,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _envelope(
            code="validation_error",
            message="Request validation failed",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            request_id=getattr(request.state, "request_id", None),
            details={"errors": jsonable_encoder(exc.errors())},
        )

    @app.exception_handler(NoResultFound)
    async def handle_no_result(request: Request, exc: NoResultFound) -> JSONResponse:
        return _envelope(
            code="not_found",
            message="Resource not found",
            status_code=status.HTTP_404_NOT_FOUND,
            request_id=getattr(request.state, "request_id", None),
        )

    @app.exception_handler(IntegrityError)
    async def handle_integrity(request: Request, exc: IntegrityError) -> JSONResponse:
        log.warning("integrity_error", error=str(exc.orig))
        return _envelope(
            code="conflict",
            message="Resource already exists or constraint violated",
            status_code=status.HTTP_409_CONFLICT,
            request_id=getattr(request.state, "request_id", None),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled_exception", path=request.url.path)
        return _envelope(
            code="internal_error",
            message="Internal server error",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            request_id=getattr(request.state, "request_id", None),
        )

"""
SignalSafe Campus - Standardized Error Handling
Ensures all errors return the shared contract envelope:
{
    "error": {
        "code": "CODE",
        "message": "User-safe message",
        "request_id": "req-uuid"
    }
}
"""

import uuid
import logging
from typing import Any, Dict, Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("signalsafe.errors")


class AppException(Exception):
    """Base application exception for SignalSafe Campus."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class UnauthorizedException(AppException):
    def __init__(self, message: str = "Authentication required or invalid token."):
        super().__init__(
            code="UNAUTHORIZED",
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class ForbiddenException(AppException):
    def __init__(self, message: str = "Access denied: insufficient permissions."):
        super().__init__(
            code="FORBIDDEN",
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
        )


class NotFoundException(AppException):
    def __init__(self, message: str = "Requested resource was not found."):
        super().__init__(
            code="NOT_FOUND",
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
        )


HTTP_422_STATUS = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", status.HTTP_422_UNPROCESSABLE_ENTITY)


class ValidationException(AppException):
    def __init__(self, message: str = "Input validation failed."):
        super().__init__(
            code="VALIDATION_ERROR",
            message=message,
            status_code=HTTP_422_STATUS,
        )


def get_request_id(request: Request) -> str:
    """Retrieve or generate a correlation request ID."""
    req_id = getattr(request.state, "request_id", None)
    if not req_id:
        req_id = f"req-{uuid.uuid4().hex[:12]}"
        request.state.request_id = req_id
    return req_id


def build_error_payload(code: str, message: str, request_id: str) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
        }
    }


async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    request_id = get_request_id(request)
    logger.warning("AppException [%s] (%s): %s", exc.code, request_id, exc.message)
    return JSONResponse(
        status_code=exc.status_code,
        content=build_error_payload(exc.code, exc.message, request_id),
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    request_id = get_request_id(request)
    # Extract the first informative validation message safely
    errors = exc.errors()
    msg = "Request validation failed."
    if errors:
        first_err = errors[0]
        field = " -> ".join(str(loc) for loc in first_err.get("loc", []) if loc != "body")
        err_msg = first_err.get("msg", "Invalid value")
        msg = f"{field}: {err_msg}" if field else err_msg

    logger.info("Validation error (%s): %s", request_id, msg)
    return JSONResponse(
        status_code=HTTP_422_STATUS,
        content=build_error_payload("VALIDATION_ERROR", msg, request_id),
    )


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    request_id = get_request_id(request)
    code = "HTTP_ERROR"
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        code = "UNAUTHORIZED"
    elif exc.status_code == status.HTTP_403_FORBIDDEN:
        code = "FORBIDDEN"
    elif exc.status_code == status.HTTP_404_NOT_FOUND:
        code = "NOT_FOUND"
    elif exc.status_code == HTTP_422_STATUS or exc.status_code == 422:
        code = "VALIDATION_ERROR"

    logger.warning("HTTPException %s (%s): %s", exc.status_code, request_id, exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content=build_error_payload(code, str(exc.detail), request_id),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = get_request_id(request)
    # Log internal details server-side only; never expose to client
    logger.exception("Unhandled server exception (%s): %s", request_id, str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=build_error_payload(
            "INTERNAL_SERVER_ERROR",
            "An unexpected server error occurred. Please contact support with the request ID.",
            request_id,
        ),
    )

"""
SignalSafe Campus - FastAPI Application Entry Point
Milestone 1 Implementation
"""

import uuid
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.core.config import settings
from backend.app.core.errors import (
    AppException,
    app_exception_handler,
    validation_exception_handler,
    http_exception_handler,
    unhandled_exception_handler,
)
from backend.app.api.v1.router import api_router


def create_application() -> FastAPI:
    """Factory function to configure and initialize the FastAPI application."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="1.0.0",
        description=(
            "SignalSafe Campus shared backend service. "
            "Authoritative threat detection, explainable risk scoring, and incident reporting."
        ),
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        docs_url=f"{settings.API_V1_STR}/docs",
        redoc_url=f"{settings.API_V1_STR}/redoc",
    )

    # 1. Request ID Correlation Middleware
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        req_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
        request.state.request_id = req_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = req_id
        return response

    # 2. CORS Middleware Configuration
    origins = settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS]
    
    # NOTE: Wildcard extension matching (`chrome-extension://.*`) is permitted ONLY for
    # Milestone 1 local development while Developer 2 tests unpacked extensions.
    # Production deployment MUST specify the exact extension ID in CORS_ORIGINS
    # (e.g. `chrome-extension://<verified_extension_id>`) and disable wildcard regex.
    origin_regex = (
        r"^(chrome-extension://.*|http://localhost:\d+|http://127\.0\.0\.1:\d+)$"
        if (settings.ALLOW_BROWSER_EXTENSIONS and settings.ENVIRONMENT != "production")
        else None
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_origin_regex=origin_regex,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # 3. Standardized Exception Handlers
    app.add_exception_handler(AppException, app_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # 4. Include Versioned API Router
    app.include_router(api_router, prefix=settings.API_V1_STR)

    @app.get("/", include_in_schema=False)
    async def root_redirect():
        return {
            "name": settings.PROJECT_NAME,
            "version": "1.0.0",
            "docs_url": f"{settings.API_V1_STR}/docs",
            "openapi_url": f"{settings.API_V1_STR}/openapi.json",
            "health_url": f"{settings.API_V1_STR}/health",
        }

    return app


app = create_application()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG,
    )

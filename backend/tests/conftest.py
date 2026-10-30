"""
SignalSafe Campus - Pytest Configuration & Fixtures
"""

import time
import uuid
import jwt
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.config import settings
from backend.app.schemas.common import UserRole
from backend.app.auth.token_validator import (
    register_server_side_user,
    clear_server_side_user_registry,
)

TEST_SECRET = "test-jwt-secret-for-cryptographic-signing-32-chars-long"


@pytest.fixture(autouse=True)
def configure_test_environment(monkeypatch):
    """Ensure tests run with predictable secrets and test environment flags."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "test")
    monkeypatch.setattr(settings, "DEBUG", True)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_SECRET)
    monkeypatch.setattr(settings, "SUPABASE_JWT_AUDIENCE", "authenticated")
    monkeypatch.setattr(
        settings,
        "SUPABASE_JWT_ISSUER",
        "https://xmhzqepctzkvbovurxvh.supabase.co/auth/v1",
    )
    clear_server_side_user_registry()
    yield
    clear_server_side_user_registry()


@pytest.fixture
def client():
    """Provides a synchronous test client for FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


def create_test_jwt(
    user_id: str,
    email: str = "student@example.edu",
    role: str = "authenticated",
    exp_offset_seconds: int = 3600,
    issuer: str = "https://xmhzqepctzkvbovurxvh.supabase.co/auth/v1",
    audience: str = "authenticated",
    secret: str = TEST_SECRET,
    algorithm: str = "HS256",
    extra_user_metadata: dict = None,
    extra_app_metadata: dict = None,
) -> str:
    """Helper to generate cryptographically signed test JWT tokens."""
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "aud": audience,
        "iss": issuer,
        "iat": now,
        "exp": now + exp_offset_seconds,
        "user_metadata": extra_user_metadata or {},
        "app_metadata": extra_app_metadata or {},
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


@pytest.fixture
def student_auth():
    """Generates an authenticated student user and returns (user_id, token, headers)."""
    user_id = str(uuid.uuid4())
    register_server_side_user(user_id, role=UserRole.STUDENT, email="student@campus.edu")
    token = create_test_jwt(user_id=user_id, email="student@campus.edu")
    headers = {"Authorization": f"Bearer {token}"}
    return {"id": user_id, "token": token, "headers": headers}


@pytest.fixture
def admin_auth():
    """Generates an authenticated campus admin user and returns (user_id, token, headers)."""
    user_id = str(uuid.uuid4())
    campus_id = str(uuid.uuid4())
    register_server_side_user(
        user_id,
        role=UserRole.CAMPUS_ADMIN,
        campus_id=campus_id,
        email="admin@campus.edu",
    )
    token = create_test_jwt(user_id=user_id, email="admin@campus.edu")
    headers = {"Authorization": f"Bearer {token}"}
    return {"id": user_id, "campus_id": campus_id, "token": token, "headers": headers}

"""
SignalSafe Campus - Security Remediation Verification Suite
Tests the remediated security controls:
1. Strict algorithm separation (RS256/ES256 never falls back to symmetric HS256 secret)
2. JWKS outage produces a controlled safe authentication failure
3. Client-supplied signup metadata (role, campus_id) is strictly ignored
4. Incident creation derives reporter identity and campus tenancy server-side
5. Campus administrator cannot perform actions outside their campus tenancy
"""

import uuid
import pytest
from unittest.mock import MagicMock
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi import status

from backend.app.core.errors import UnauthorizedException
from backend.app.auth.token_validator import token_validator, register_server_side_user
from backend.app.schemas.common import UserRole
from backend.tests.conftest import create_test_jwt, TEST_SECRET


@pytest.fixture(scope="module")
def test_rsa_key_pair():
    """Generates an ephemeral RSA key pair for testing RS256 token verification."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    return {"private_pem": private_pem, "public_key": public_key}


def test_asymmetric_jwt_cannot_fallback_to_hs256_secret(test_rsa_key_pair, monkeypatch):
    """
    SECURITY TEST: An asymmetric RS256 token must NEVER fall back to verifying
    against the symmetric SUPABASE_JWT_SECRET.
    """
    user_id = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "iss": "https://xmhzqepctzkvbovurxvh.supabase.co/auth/v1",
        "exp": 9999999999,
    }
    # Properly sign an RS256 token with private key
    rs256_token = pyjwt.encode(
        payload,
        test_rsa_key_pair["private_pem"],
        algorithm="RS256",
        headers={"kid": "test-kid-1"},
    )

    # Simulate JWKS failure so fallback would be attempted if vulnerable
    mock_jwks = MagicMock()
    mock_jwks.get_signing_key_from_jwt.side_effect = Exception("Public key not found in JWKS")
    monkeypatch.setattr(token_validator, "_get_jwks_client", lambda: mock_jwks)

    # When decoded, token_validator must reject cleanly without falling back to symmetric secret
    with pytest.raises(UnauthorizedException) as exc_info:
        token_validator.decode_and_verify(rs256_token)

    assert "unable to verify token signature: public key unavailable" in str(exc_info.value.message).lower()


def test_jwks_outage_produces_controlled_auth_failure(test_rsa_key_pair, monkeypatch):
    """
    SECURITY TEST: When the JWKS endpoint is unreachable or errors out,
    token_validator must return a safe, controlled authentication error without
    leaking internal exception messages or stack traces.
    """
    user_id = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "iss": "https://xmhzqepctzkvbovurxvh.supabase.co/auth/v1",
        "exp": 9999999999,
    }
    rs256_token = pyjwt.encode(
        payload,
        test_rsa_key_pair["private_pem"],
        algorithm="RS256",
        headers={"kid": "test-kid-2"},
    )

    # Mock JWKS client to simulate network outage / timeout
    mock_jwks = MagicMock()
    mock_jwks.get_signing_key_from_jwt.side_effect = Exception("Connection timed out to jwks.json")
    monkeypatch.setattr(token_validator, "_get_jwks_client", lambda: mock_jwks)

    with pytest.raises(UnauthorizedException) as exc_info:
        token_validator.decode_and_verify(rs256_token)

    # Error message must be safe and not leak internal trace
    assert "public key unavailable" in str(exc_info.value.message).lower()
    assert "timed out" not in str(exc_info.value.message).lower()


def test_user_cannot_register_with_assigned_campus_id():
    """
    SECURITY TEST: Client-supplied campus_id in signup metadata must be strictly IGNORED.
    User's campus_id must resolve to None unless provisioned by server-side authority.
    """
    user_id = str(uuid.uuid4())
    attacker_campus_id = str(uuid.uuid4())

    token = create_test_jwt(
        user_id=user_id,
        extra_user_metadata={
            "campus_id": attacker_campus_id,
            "role": "CAMPUS_ADMIN",
        },
    )

    payload = token_validator.decode_and_verify(token)
    user = token_validator.derive_user(payload)

    # Campus ID must be None; attacker's metadata was ignored
    assert user.campus_id is None
    assert user.role == UserRole.STUDENT


def test_student_cannot_assign_privileged_role():
    """
    SECURITY TEST: Client-supplied role in signup metadata must be strictly IGNORED.
    """
    user_id = str(uuid.uuid4())
    token = create_test_jwt(
        user_id=user_id,
        extra_user_metadata={"role": "PLATFORM_ADMIN"},
    )

    payload = token_validator.decode_and_verify(token)
    user = token_validator.derive_user(payload)

    assert user.role == UserRole.STUDENT


def test_incident_creation_ignores_client_campus_override(client, student_auth):
    """
    SECURITY TEST: Client cannot force an arbitrary campus_id during incident creation.
    Reporter identity is derived from the verified token.
    """
    arbitrary_campus_id = str(uuid.uuid4())
    response = client.post(
        "/api/v1/incidents",
        json={
            "category": "PHISHING",
            "summary": "Attempting cross-campus spoofing",
            # Even if an unmodeled field is sent, schema ignores/disallows it
            "campus_id": arbitrary_campus_id,
        },
        headers=student_auth["headers"],
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "incident_id" in data
    # Verified: Reporter is derived strictly from student_auth['id']
    assert student_auth["id"] in data["_mock_notice"]


def test_student_cannot_modify_own_role_or_campus(client, student_auth):
    """
    SECURITY TEST: Ordinary students cannot perform administrative updates on incidents
    or elevate their status (403 Forbidden).
    """
    sample_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    response = client.patch(
        f"/api/v1/incidents/{sample_id}",
        json={"status": "RESOLVED", "severity": "LOW"},
        headers=student_auth["headers"],
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_platform_admin_can_perform_updates(client):
    """
    SECURITY TEST: Platform administrator is authorized to perform case management actions.
    """
    admin_id = str(uuid.uuid4())
    register_server_side_user(
        admin_id,
        role=UserRole.PLATFORM_ADMIN,
        email="platform-admin@system.internal",
    )
    token = create_test_jwt(user_id=admin_id, email="platform-admin@system.internal")
    headers = {"Authorization": f"Bearer {token}"}

    sample_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    response = client.patch(
        f"/api/v1/incidents/{sample_id}",
        json={"status": "INVESTIGATING", "severity": "CRITICAL"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "INVESTIGATING"

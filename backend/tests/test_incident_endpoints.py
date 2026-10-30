"""
SignalSafe Campus - Incident Management Tests
Validates authentication enforcement, reporter attribution, and admin updates.
"""

from fastapi import status


def test_create_incident_unauthenticated(client):
    """Anonymous incident submission must be rejected with 401."""
    response = client.post(
        "/api/v1/incidents",
        json={
            "category": "PHISHING",
            "summary": "Suspicious email received",
        },
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_create_incident_authenticated(client, student_auth):
    """Authenticated student can create incident; reporter identity is derived server-side."""
    response = client.post(
        "/api/v1/incidents",
        json={
            "category": "PHISHING",
            "summary": "Phishing email targeting financial aid",
            "description": "Email contains link asking for campus portal credentials.",
        },
        headers=student_auth["headers"],
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "incident_id" in data
    assert data["status"] == "SUBMITTED"
    assert "created_at" in data
    assert "_mock_notice" in data


def test_create_incident_validation_failure(client, student_auth):
    """Reject invalid category or missing summary."""
    response = client.post(
        "/api/v1/incidents",
        json={
            "category": "INVALID_CATEGORY",
            "summary": "Short",
        },
        headers=student_auth["headers"],
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_list_incidents_unauthenticated(client):
    """List incidents requires authentication."""
    response = client.get("/api/v1/incidents")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_list_incidents_authenticated(client, student_auth):
    """Authenticated user can list visible incidents."""
    response = client.get("/api/v1/incidents", headers=student_auth["headers"])
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data


def test_get_incident_detail(client, student_auth):
    """Authenticated user can retrieve incident detail."""
    sample_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    response = client.get(f"/api/v1/incidents/{sample_id}", headers=student_auth["headers"])
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == sample_id
    assert "category" in data
    assert "status" in data
    assert "severity" in data


def test_update_incident_student_forbidden(client, student_auth):
    """Students cannot perform administrative updates on incidents (403 Forbidden)."""
    sample_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    response = client.patch(
        f"/api/v1/incidents/{sample_id}",
        json={"status": "INVESTIGATING", "severity": "CRITICAL"},
        headers=student_auth["headers"],
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_update_incident_admin_success(client, admin_auth):
    """Campus admin can update incident workflow fields."""
    sample_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    response = client.patch(
        f"/api/v1/incidents/{sample_id}",
        json={
            "status": "INVESTIGATING",
            "severity": "HIGH",
            "note": "Incident triaged by security team.",
        },
        headers=admin_auth["headers"],
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "INVESTIGATING"
    assert data["severity"] == "HIGH"

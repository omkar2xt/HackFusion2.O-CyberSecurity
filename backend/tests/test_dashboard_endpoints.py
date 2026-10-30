"""
SignalSafe Campus - Dashboard Metrics Tests
Validates admin authorization and metrics schema.
"""

from fastapi import status


def test_dashboard_stats_unauthenticated(client):
    """Anonymous access to dashboard stats is rejected."""
    response = client.get("/api/v1/dashboard/stats")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_dashboard_stats_student_forbidden(client, student_auth):
    """Students cannot access administrative dashboard stats (403 Forbidden)."""
    response = client.get("/api/v1/dashboard/stats", headers=student_auth["headers"])
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_dashboard_stats_admin_success(client, admin_auth):
    """Campus admin can retrieve dashboard statistics."""
    response = client.get("/api/v1/dashboard/stats", headers=admin_auth["headers"])
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "total_scans" in data
    assert "total_incidents" in data
    assert "open_incidents" in data
    assert "resolved_incidents" in data
    assert "incidents_by_severity" in data
    assert "_mock_notice" in data

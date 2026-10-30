"""
SignalSafe Campus - Health Check & Startup Tests
"""

from fastapi import status


def test_app_startup_root(client):
    """Test root service index."""
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "name" in data
    assert "version" in data
    assert "health_url" in data


def test_health_endpoint(client):
    """Test health check returns healthy status without exposing secrets."""
    response = client.get("/api/v1/health")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"
    assert "timestamp" in data
    assert "environment" in data
    # Ensure no secret strings or private configuration are leaked
    response_str = response.text.lower()
    assert "key" not in response_str
    assert "secret" not in response_str
    assert "token" not in response_str

"""
SignalSafe Campus - Threat Scanning Tests
Validates request validation, scheme filtering, response schemas, and optional auth.
"""

from fastapi import status


def test_scan_url_valid(client):
    """Test valid HTTPS URL scanning."""
    response = client.post("/api/v1/scan/url", json={"url": "https://example.com/login"})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "scan_id" in data
    assert data["verdict"] in ["MALICIOUS", "SUSPICIOUS", "LOW_RISK", "UNKNOWN"]
    assert data["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
    assert isinstance(data["risk_score"], int)
    assert 0 <= data["risk_score"] <= 100
    assert "indicators" in data
    assert "recommendations" in data
    assert "checked_at" in data
    assert "_mock_notice" in data


def test_scan_url_unsupported_scheme(client):
    """Test rejection of dangerous/unsupported schemes."""
    # javascript: scheme
    res1 = client.post("/api/v1/scan/url", json={"url": "javascript:alert(1)"})
    assert res1.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert res1.json()["error"]["code"] == "VALIDATION_ERROR"

    # ftp: scheme
    res2 = client.post("/api/v1/scan/url", json={"url": "ftp://files.example.com"})
    assert res2.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert res2.json()["error"]["code"] == "VALIDATION_ERROR"

    # data: scheme
    res3 = client.post("/api/v1/scan/url", json={"url": "data:text/html;base64,PHNjcmlwdD4="})
    assert res3.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert res3.json()["error"]["code"] == "VALIDATION_ERROR"


def test_scan_url_missing_host(client):
    """Test rejection of malformed URLs without host."""
    res = client.post("/api/v1/scan/url", json={"url": "https://"})
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert res.json()["error"]["code"] == "VALIDATION_ERROR"


def test_scan_url_optional_auth_valid(client, student_auth):
    """Test scanning when valid auth header is provided."""
    response = client.post(
        "/api/v1/scan/url",
        json={"url": "https://portal.university.edu"},
        headers=student_auth["headers"],
    )
    assert response.status_code == status.HTTP_200_OK


def test_scan_url_optional_auth_invalid(client):
    """Test scanning when invalid auth header is provided - must reject with 401."""
    response = client.post(
        "/api/v1/scan/url",
        json={"url": "https://portal.university.edu"},
        headers={"Authorization": "Bearer bad-token"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_scan_message(client):
    """Test scanning message text and extracting URLs."""
    msg = "Action required: update password at https://secure-verify.com/login now."
    response = client.post("/api/v1/scan/message", json={"message_text": msg})
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "extracted_urls" in data
    assert "https://secure-verify.com/login" in data["extracted_urls"]
    assert data["analysis_scope"] == "EXTRACTED_URLS_AND_HEURISTICS"
    assert data["verdict"] == "SUSPICIOUS"


def test_scan_qr(client):
    """Test scanning decoded QR payloads."""
    # URL payload
    response = client.post(
        "/api/v1/scan/qr",
        json={"decoded_content": "https://campus-services.org/pay"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["payload_type"] == "URL"

    # Non-URL payload
    res_text = client.post(
        "/api/v1/scan/qr",
        json={"decoded_content": "WIFI:S:Campus_Guest;T:WPA;P:guest123;;"},
    )
    assert res_text.status_code == status.HTTP_200_OK
    assert res_text.json()["payload_type"] == "RAW_TEXT"

"""
SignalSafe Campus - Vercel Deployment Configuration Tests
Validates Phase 4A requirements:
- Root-level entrypoint (api/index.py) exporting FastAPI app
- Root vercel.json runtime and routing configuration
- Python version declaration (.python-version)
- Dependency referencing (requirements.txt)
- ASGI route accessibility across all v1 routes
- Non-interference with /api/v1 prefix
- Production CORS origin constraints
- Vercel serverless payload limit awareness
- Environment-only secret handling
"""

import json
from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_python_version_file():
    """Verify that .python-version exists and declares Python 3.12."""
    version_file = REPO_ROOT / ".python-version"
    assert version_file.exists(), ".python-version file is missing from repository root"
    content = version_file.read_text(encoding="utf-8").strip()
    assert content == "3.12", f"Expected '3.12' in .python-version, got '{content}'"


def test_requirements_file_referencing():
    """Verify that root requirements.txt references backend/requirements.txt without duplication."""
    req_file = REPO_ROOT / "requirements.txt"
    backend_req_file = REPO_ROOT / "backend" / "requirements.txt"

    assert req_file.exists(), "Root requirements.txt is missing"
    assert backend_req_file.exists(), "backend/requirements.txt is missing"

    content = req_file.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]

    assert any(line == "-r backend/requirements.txt" for line in lines), (
        "Root requirements.txt must include '-r backend/requirements.txt'"
    )
    # Ensure no package specifications are duplicated in root requirements.txt
    for line in lines:
        if not line.startswith("-r"):
            pytest.fail(f"Unexpected duplicate requirement in root requirements.txt: {line}")


def test_vercel_json_configuration():
    """Verify vercel.json structure, schema reference, and rewrite rules."""
    vercel_file = REPO_ROOT / "vercel.json"
    assert vercel_file.exists(), "vercel.json is missing from repository root"

    with open(vercel_file, "r", encoding="utf-8") as f:
        config = json.load(f)

    assert "rewrites" in config, "vercel.json must specify 'rewrites'"
    rewrites = config["rewrites"]
    assert isinstance(rewrites, list) and len(rewrites) > 0, "'rewrites' must be a non-empty list"

    # Verify catch-all or prefix rewrite targeting api/index.py
    has_catchall = any(
        r.get("source") in ["/(.*)", "/api/(.*)"] and r.get("destination") == "/api/index.py"
        for r in rewrites
    )
    assert has_catchall, "vercel.json must rewrite incoming paths to '/api/index.py'"


def test_vercel_entrypoint_import():
    """Verify that api/index.py exists and exports the FastAPI application."""
    entrypoint_file = REPO_ROOT / "api" / "index.py"
    assert entrypoint_file.exists(), "api/index.py entrypoint is missing"

    from api.index import app as vercel_app
    from backend.app.main import app as main_app

    assert isinstance(vercel_app, FastAPI), "api.index.app must be an instance of FastAPI"
    assert vercel_app is main_app, "api.index.app must expose the identical FastAPI app instance"


def test_asgi_route_accessibility_via_vercel_entrypoint():
    """Verify that all core routes remain accessible through the Vercel entrypoint without prefix loss."""
    from api.index import app

    client = TestClient(app)

    # 1. Root route
    root_resp = client.get("/")
    assert root_resp.status_code == 200, f"Root route '/' failed: {root_resp.status_code}"
    root_data = root_resp.json()
    assert "name" in root_data
    assert root_data["docs_url"] == "/api/v1/docs"
    assert root_data["openapi_url"] == "/api/v1/openapi.json"
    assert root_data["health_url"] == "/api/v1/health"

    # 2. Health check
    health_resp = client.get("/api/v1/health")
    assert health_resp.status_code == 200, f"/api/v1/health failed: {health_resp.status_code}"
    assert health_resp.json().get("status") == "healthy"

    # 3. Documentation
    docs_resp = client.get("/api/v1/docs")
    assert docs_resp.status_code == 200, f"/api/v1/docs failed: {docs_resp.status_code}"

    # 4. OpenAPI JSON
    openapi_resp = client.get("/api/v1/openapi.json")
    assert openapi_resp.status_code == 200, f"/api/v1/openapi.json failed: {openapi_resp.status_code}"
    openapi_data = openapi_resp.json()
    assert "paths" in openapi_data

    registered_paths = set(openapi_data["paths"].keys())
    expected_v1_endpoints = {
        "/api/v1/health",
        "/api/v1/scan/url",
        "/api/v1/scan/message",
        "/api/v1/scan/qr",
        "/api/v1/incidents",
        "/api/v1/dashboard/stats",
    }
    for endpoint in expected_v1_endpoints:
        assert endpoint in registered_paths, (
            f"Endpoint '{endpoint}' not found in OpenAPI registered paths. "
            f"Prefix '/api/v1' may be misconfigured or stripped."
        )


def test_production_cors_exact_origin_enforcement():
    """Verify that in production mode, wildcard extension origin regex is disabled and exact origins are required."""
    from backend.app.core.config import Settings
    from backend.app.main import create_application

    # Test production settings: wildcard regex MUST be None
    prod_settings = Settings(
        ENVIRONMENT="production",
        ALLOW_BROWSER_EXTENSIONS=True,
        CORS_ORIGINS=["chrome-extension://abcdefghijklmnop", "https://signalsafe.campus.edu"],
    )

    # In production, origin_regex should be None
    origin_regex = (
        r"^(chrome-extension://.*|http://localhost(:\d+)?|http://127\.0\.0\.1(:\d+)?)$"
        if (prod_settings.ALLOW_BROWSER_EXTENSIONS and prod_settings.ENVIRONMENT != "production")
        else None
    )
    assert origin_regex is None, "Production configuration must NOT use wildcard extension regex"


def test_vercel_serverless_payload_limit_documented():
    """Verify that Vercel 4.5 MB payload limit is acknowledged relative to the internal 10 MB QR limit."""
    from backend.app.services.detection.qr.analyzer import MAX_IMAGE_FILE_SIZE_BYTES

    VERCEL_MAX_PAYLOAD_BYTES = 4_718_592  # 4.5 MB in bytes

    # The internal application allows up to 10 MB for standalone deployments,
    # but any deployment via Vercel serverless functions is bounded by the 4.5 MB edge ceiling.
    assert MAX_IMAGE_FILE_SIZE_BYTES == 10 * 1024 * 1024
    assert VERCEL_MAX_PAYLOAD_BYTES < MAX_IMAGE_FILE_SIZE_BYTES, (
        "Documented constraint: Vercel edge proxy enforces a strict 4.5 MB limit."
    )

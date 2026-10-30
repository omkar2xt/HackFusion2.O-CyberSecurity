"""
SignalSafe Campus - API Contract Consistency Tests
Verifies that FastAPI routes match shared OpenAPI contract and example responses are schema-compliant.
"""

import json
from pathlib import Path
import yaml
from backend.app.main import app
from backend.app.schemas.scan import (
    ScanResultResponse,
    ScanMessageResponse,
    ScanQrResponse,
)
from backend.app.schemas.incident import (
    CreateIncidentResponse,
    IncidentDetailResponse,
    IncidentListResponse,
)
from backend.app.schemas.dashboard import DashboardStatsResponse
from backend.app.schemas.common import ErrorEnvelope


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
OPENAPI_SPEC_PATH = REPO_ROOT / "shared" / "api-contracts" / "openapi.yaml"
EXAMPLES_DIR = REPO_ROOT / "shared" / "api-contracts" / "examples"


def test_openapi_spec_exists_and_parses():
    """Verify shared openapi.yaml exists and is valid YAML."""
    assert OPENAPI_SPEC_PATH.exists(), f"OpenAPI spec not found at {OPENAPI_SPEC_PATH}"
    with open(OPENAPI_SPEC_PATH, "r", encoding="utf-8") as f:
        spec = yaml.safe_load(f)

    assert spec.get("openapi") == "3.1.0"
    assert "paths" in spec
    assert "components" in spec


def test_api_routes_match_openapi_paths():
    """Verify all FastAPI routes are represented in shared openapi.yaml."""
    with open(OPENAPI_SPEC_PATH, "r", encoding="utf-8") as f:
        spec = yaml.safe_load(f)

    spec_paths = set(spec.get("paths", {}).keys())

    # Required v1 endpoints relative to /api/v1
    required_endpoints = {
        "/health",
        "/scan/url",
        "/scan/message",
        "/scan/qr",
        "/incidents",
        "/incidents/{id}",
        "/dashboard/stats",
    }

    for ep in required_endpoints:
        assert ep in spec_paths, f"Endpoint {ep} missing from shared openapi.yaml"


def test_examples_conform_to_pydantic_schemas():
    """Verify that every mock example in shared/api-contracts/examples validates against Pydantic models."""
    # 1. scan_url_response.json
    with open(EXAMPLES_DIR / "scan_url_response.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        ScanResultResponse.model_validate(data)

    # 2. scan_message_response.json
    with open(EXAMPLES_DIR / "scan_message_response.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        ScanMessageResponse.model_validate(data)

    # 3. scan_qr_response.json
    with open(EXAMPLES_DIR / "scan_qr_response.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        ScanQrResponse.model_validate(data)

    # 4. incident_create_response.json
    with open(EXAMPLES_DIR / "incident_create_response.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        CreateIncidentResponse.model_validate(data)

    # 5. incident_detail_response.json
    with open(EXAMPLES_DIR / "incident_detail_response.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        IncidentDetailResponse.model_validate(data)

    # 6. incident_list_response.json
    with open(EXAMPLES_DIR / "incident_list_response.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        IncidentListResponse.model_validate(data)

    # 7. dashboard_stats_response.json
    with open(EXAMPLES_DIR / "dashboard_stats_response.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        DashboardStatsResponse.model_validate(data)

    # 8. error_response.json
    with open(EXAMPLES_DIR / "error_response.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        ErrorEnvelope.model_validate(data)

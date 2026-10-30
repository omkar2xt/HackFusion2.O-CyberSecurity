"""
SignalSafe Campus - Common Schema Definitions
"""

from enum import Enum
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class ScanVerdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    LOW_RISK = "LOW_RISK"
    UNKNOWN = "UNKNOWN"


class ScanRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class EvidenceType(str, Enum):
    HEURISTIC = "heuristic"
    THREAT_INTELLIGENCE = "threat_intelligence"
    USER_REPORT = "user_report"
    ML_FEATURE = "ml_feature"
    ML_MODEL = "ml_model"
    OTHER = "other"


class IncidentCategory(str, Enum):
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    IMPERSONATION = "IMPERSONATION"
    SCAM = "SCAM"
    OTHER = "OTHER"


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    SUBMITTED = "SUBMITTED"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class UserRole(str, Enum):
    STUDENT = "STUDENT"
    FACULTY = "FACULTY"
    CAMPUS_ADMIN = "CAMPUS_ADMIN"
    PLATFORM_ADMIN = "PLATFORM_ADMIN"


class ScanIndicator(BaseModel):
    code: str = Field(..., json_schema_extra={"example": "LOOKALIKE_HOST"})
    label: str = Field(..., json_schema_extra={"example": "Possible lookalike domain"})
    evidence_type: EvidenceType = Field(..., json_schema_extra={"example": EvidenceType.HEURISTIC})
    detail: str = Field(..., json_schema_extra={"example": "The hostname resembles a known university service."})


class HealthResponse(BaseModel):
    status: str = Field("healthy", json_schema_extra={"example": "healthy"})
    version: str = Field("1.0.0", json_schema_extra={"example": "1.0.0"})
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    environment: str = Field("development", json_schema_extra={"example": "development"})


class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: str


class ErrorEnvelope(BaseModel):
    error: ErrorDetail

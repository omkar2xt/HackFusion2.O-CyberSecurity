"""
SignalSafe Campus - Model Inference Interfaces
Module: backend/app/services/detection/model_adapters/base.py

Defines model-independent abstract interfaces, metadata definitions,
and prediction containers for URL and QR ML classification models.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ModelType(str, Enum):
    ONNX = "ONNX"
    JOBLIB = "JOBLIB"
    MOCK = "MOCK"


class PredictionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    UNAVAILABLE = "UNAVAILABLE"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ModelMetadata:
    """Metadata describing a loaded or registered ML model artifact."""
    name: str
    version: str
    model_type: ModelType
    feature_schema_version: str
    artifact_path: Optional[str] = None
    sha256_checksum: Optional[str] = None
    is_mock: bool = False
    calibrated_probabilities: bool = False
    decision_threshold: float = 0.50
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class ModelPrediction:
    """Standardized prediction result produced by a model adapter."""
    model_name: str
    model_version: str
    status: PredictionStatus
    prediction: int  # 0 = Benign/Legitimate, 1 = Phishing/Malicious
    probability: Optional[float]  # Calibrated probability of malicious class (0.0 to 1.0)
    confidence: float  # Confidence score (0.0 to 1.0)
    is_mock: bool
    inference_time_ms: float
    error_reason: Optional[str] = None

    @property
    def is_phishing(self) -> bool:
        return self.status == PredictionStatus.SUCCESS and self.prediction == 1


class BaseModelAdapter(ABC):
    """Abstract interface for model inference adapters."""

    @abstractmethod
    def predict(self, features: Any) -> ModelPrediction:
        """Executes inference on the input feature vector or payload."""
        pass

    @abstractmethod
    def is_ready(self) -> bool:
        """Returns True if the model artifact is loaded and ready for inference."""
        pass

    @abstractmethod
    def get_metadata(self) -> ModelMetadata:
        """Returns metadata for the current model adapter."""
        pass

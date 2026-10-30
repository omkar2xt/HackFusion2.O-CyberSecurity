"""
SignalSafe Campus - Model Adapters Package
"""

from backend.app.services.detection.model_adapters.base import (
    BaseModelAdapter,
    ModelMetadata,
    ModelPrediction,
    ModelType,
    PredictionStatus,
)
from backend.app.services.detection.model_adapters.url_adapter import URLModelAdapter
from backend.app.services.detection.model_adapters.qr_adapter import QRModelAdapter
from backend.app.services.detection.model_adapters.registry import (
    ModelRegistry,
    model_registry,
)

__all__ = [
    "BaseModelAdapter",
    "ModelMetadata",
    "ModelPrediction",
    "ModelType",
    "PredictionStatus",
    "URLModelAdapter",
    "QRModelAdapter",
    "ModelRegistry",
    "model_registry",
]

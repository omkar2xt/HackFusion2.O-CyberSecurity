"""
SignalSafe Campus - Model Registry
Module: backend/app/services/detection/model_adapters/registry.py

Central registry managing model adapters, version checks, and lazy loading.
"""

from typing import Dict, Optional
from backend.app.services.detection.model_adapters.base import BaseModelAdapter, ModelMetadata
from backend.app.services.detection.model_adapters.url_adapter import URLModelAdapter
from backend.app.services.detection.model_adapters.qr_adapter import QRModelAdapter


class ModelRegistry:
    """Manages active ML model adapters for the detection engine."""

    def __init__(self):
        self._url_adapter: Optional[URLModelAdapter] = None
        self._qr_adapter: Optional[QRModelAdapter] = None

    def get_url_model(self) -> URLModelAdapter:
        if self._url_adapter is None:
            self._url_adapter = URLModelAdapter()
        return self._url_adapter

    def get_qr_model(self) -> QRModelAdapter:
        if self._qr_adapter is None:
            self._qr_adapter = QRModelAdapter()
        return self._qr_adapter

    def get_registry_status(self) -> Dict[str, ModelMetadata]:
        return {
            "url_model": self.get_url_model().get_metadata(),
            "qr_model": self.get_qr_model().get_metadata(),
        }


# Global singleton instance
model_registry = ModelRegistry()

"""
SignalSafe Campus - Model Registry
Module: backend/app/services/detection/model_adapters/registry.py

Central registry managing model adapters, version checks, and lazy loading.
"""

from typing import Any, Dict, Optional
from backend.app.services.detection.model_adapters.base import BaseModelAdapter, ModelMetadata
from backend.app.services.detection.model_adapters.url_adapter import URLModelAdapter
from backend.app.services.detection.model_adapters.qr_adapter import QRModelAdapter
from backend.app.services.detection.model_adapters.attachment_adapter import AttachmentModelAdapter


class ModelRegistry:
    """Manages active ML model adapters for the detection engine."""

    def __init__(self):
        self._url_adapter: Optional[URLModelAdapter] = None
        self._qr_adapter: Optional[QRModelAdapter] = None
        self._attachment_adapter: Optional[AttachmentModelAdapter] = None

    def get_url_model(self) -> URLModelAdapter:
        if self._url_adapter is None:
            self._url_adapter = URLModelAdapter()
        return self._url_adapter

    def get_qr_model(self) -> QRModelAdapter:
        if self._qr_adapter is None:
            self._qr_adapter = QRModelAdapter()
        return self._qr_adapter

    def get_attachment_model(self) -> AttachmentModelAdapter:
        if self._attachment_adapter is None:
            self._attachment_adapter = AttachmentModelAdapter()
        return self._attachment_adapter

    def get_registry_status(self) -> Dict[str, Any]:
        return {
            "url_model": self.get_url_model().get_metadata(),
            "qr_model": self.get_qr_model().get_metadata(),
            "attachment_models": {
                fmt: self.get_attachment_model().get_format_metadata(fmt)
                for fmt in ["excel", "word", "pdf", "html"]
            },
        }


# Global singleton instance
model_registry = ModelRegistry()

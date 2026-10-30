"""
SignalSafe Campus - Multi-Format Attachment Model Adapter
Module: backend/app/services/detection/model_adapters/attachment_adapter.py

Adapter for Model D (Multi-Format Attachment & Document Classifier).
Consumes features extracted according to CIC 2025 Multi-Format Dataset.
Supports Excel, Word, PDF, and HTML threat classification.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from backend.app.services.detection.model_adapters.base import (
    BaseModelAdapter,
    ModelMetadata,
    ModelPrediction,
    ModelType,
    PredictionStatus,
)


class AttachmentModelAdapter(BaseModelAdapter):
    """
    Multi-format attachment classifier for Excel, Word, PDF, and HTML documents.
    """

    def __init__(self, models_dir: Optional[str] = None):
        self.candidate_dirs = [
            models_dir,
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "detection")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "detection")),
            os.path.join("SignalSafe_Campus", "models", "production"),
            os.path.abspath(os.path.join("SignalSafe_Campus", "models", "production")),
        ]
        self._models: Dict[str, Any] = {}
        self._metadata: Dict[str, ModelMetadata] = {}
        self._feature_schemas: Dict[str, List[str]] = {}
        self._initialize_all_formats()

    def _compute_checksum(self, filepath: str) -> str:
        sha = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest()

    def _resolve_artifact(self, filename: str) -> Optional[str]:
        for d in self.candidate_dirs:
            if d:
                full_path = os.path.join(d, filename)
                if os.path.exists(full_path):
                    return full_path
        return None

    def _initialize_all_formats(self):
        formats = ["excel", "word", "pdf", "html"]
        for fmt in formats:
            joblib_path = self._resolve_artifact(f"{fmt}_classifier_best.joblib")
            meta_path = self._resolve_artifact(f"{fmt}_classifier_metadata.json")

            if joblib_path and meta_path and os.path.exists(joblib_path) and os.path.exists(meta_path):
                try:
                    with open(meta_path, "r") as mf:
                        meta_json = json.load(mf)

                    self._feature_schemas[fmt] = meta_json.get("features", [])
                    checksum = self._compute_checksum(joblib_path)
                    model = joblib.load(joblib_path)
                    self._models[fmt] = model

                    self._metadata[fmt] = ModelMetadata(
                        name=f"{fmt.capitalize()}Classifier",
                        version="1.0.0",
                        model_type=ModelType.JOBLIB,
                        feature_schema_version="cic-2025-v1",
                        artifact_path=joblib_path,
                        sha256_checksum=checksum,
                        is_mock=False,
                        calibrated_probabilities=True,
                        decision_threshold=0.50,
                    )
                except Exception as e:
                    print(f"Failed to load {fmt} model: {e}")
            else:
                self._metadata[fmt] = ModelMetadata(
                    name=f"{fmt.capitalize()}Classifier-Mock",
                    version="1.0.0",
                    model_type=ModelType.MOCK,
                    feature_schema_version="cic-2025-v1",
                    is_mock=True,
                    calibrated_probabilities=False,
                    decision_threshold=0.50,
                )

    def is_ready(self) -> bool:
        """Returns True if at least one attachment model is loaded."""
        return len(self._models) > 0

    def get_metadata(self) -> ModelMetadata:
        return self._metadata.get("excel", ModelMetadata(
            name="AttachmentClassifier",
            version="1.0.0",
            model_type=ModelType.JOBLIB,
            feature_schema_version="cic-2025-v1",
            is_mock=False,
        ))

    def get_format_metadata(self, fmt: str) -> Optional[ModelMetadata]:
        return self._metadata.get(fmt.lower())

    def predict(self, features: Any) -> ModelPrediction:
        """Default predict routing to excel or infer format from payload."""
        if isinstance(features, dict) and "format" in features and "features" in features:
            return self.predict_features(features["format"], features["features"])
        return self.predict_features("excel", features if isinstance(features, dict) else {})

    def predict_features(self, fmt: str, feature_dict: Dict[str, float]) -> ModelPrediction:
        """
        Runs inference on extracted attachment feature dict for a specific format.
        """
        fmt = fmt.lower()
        start_time = time.time()

        if fmt not in self._models:
            return ModelPrediction(
                model_name=f"{fmt.capitalize()}Classifier",
                model_version="1.0.0",
                status=PredictionStatus.UNAVAILABLE,
                prediction=0,
                probability=0.0,
                confidence=0.5,
                is_mock=True,
                inference_time_ms=(time.time() - start_time) * 1000.0,
                error_reason=f"Model for format '{fmt}' is not loaded.",
            )

        model = self._models[fmt]
        expected_features = self._feature_schemas.get(fmt, [])
        vector = [float(feature_dict.get(feat, 0.0)) for feat in expected_features]

        try:
            X = np.array([vector], dtype=np.float32)
            pred = int(model.predict(X)[0])

            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(X)[0]
                prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            else:
                prob = 1.0 if pred == 1 else 0.0

            conf = float(abs(prob - 0.5) * 2.0)
            elapsed = (time.time() - start_time) * 1000.0

            return ModelPrediction(
                model_name=f"{fmt.capitalize()}Classifier",
                model_version="1.0.0",
                status=PredictionStatus.SUCCESS,
                prediction=pred,
                probability=prob,
                confidence=conf,
                is_mock=False,
                inference_time_ms=elapsed,
            )
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000.0
            return ModelPrediction(
                model_name=f"{fmt.capitalize()}Classifier",
                model_version="1.0.0",
                status=PredictionStatus.ERROR,
                prediction=0,
                probability=0.0,
                confidence=0.0,
                is_mock=True,
                inference_time_ms=elapsed,
                error_reason=str(e),
            )

"""
SignalSafe Campus - QR Image Classification Model Adapter
Module: backend/app/services/detection/model_adapters/qr_adapter.py

Adapter for Model B (QR Image Visual Phishing Classifier).
Evaluates visual distortions, density patterns, and image-based features.
Kept strictly separate from decoded destination URL classification.
"""

import hashlib
import io
import os
import time
from typing import Any, Optional

from PIL import Image

from backend.app.services.detection.model_adapters.base import (
    BaseModelAdapter,
    ModelMetadata,
    ModelPrediction,
    ModelType,
    PredictionStatus,
)


class QRModelAdapter(BaseModelAdapter):
    """
    Model adapter for QR code image visual classification (Model B).
    Evaluates image tensors independently from the decoded URL payload.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        expected_checksum: Optional[str] = None,
        decision_threshold: float = 0.50,
    ):
        self.model_path = model_path or os.environ.get("QR_MODEL_PATH", "models/qr_classifier_v1.onnx")
        self.expected_checksum = expected_checksum
        self.decision_threshold = decision_threshold
        self._session: Any = None
        self._metadata: ModelMetadata = self._initialize_adapter()

    def _initialize_adapter(self) -> ModelMetadata:
        if self.model_path and os.path.exists(self.model_path):
            try:
                actual_hash = self._compute_checksum(self.model_path)
                if self.expected_checksum and actual_hash.lower() != self.expected_checksum.lower():
                    print(f"[SECURITY ALERT] QR model artifact checksum mismatch for {self.model_path}")
                    return self._create_mock_metadata(f"Checksum mismatch: expected {self.expected_checksum}")

                if self.model_path.endswith(".onnx"):
                    import onnxruntime as ort
                    self._session = ort.InferenceSession(
                        self.model_path,
                        providers=["CPUExecutionProvider"],
                    )
                    return ModelMetadata(
                        name="QRImageClassifier-ONNX",
                        version="1.0.0",
                        model_type=ModelType.ONNX,
                        feature_schema_version="visual_v1",
                        artifact_path=self.model_path,
                        sha256_checksum=actual_hash,
                        is_mock=False,
                        calibrated_probabilities=True,
                        decision_threshold=self.decision_threshold,
                    )
            except Exception as exc:
                print(f"[WARN] Failed to load QR model artifact at {self.model_path}: {exc}")
                return self._create_mock_metadata(f"Artifact load failure: {exc}")

        return self._create_mock_metadata("Artifact not yet deployed (independent training in progress)")

    def _create_mock_metadata(self, note: str) -> ModelMetadata:
        return ModelMetadata(
            name="QRImageClassifier-MockAdapter",
            version="1.0.0-mock",
            model_type=ModelType.MOCK,
            feature_schema_version="visual_v1",
            artifact_path=self.model_path,
            sha256_checksum=None,
            is_mock=True,
            calibrated_probabilities=False,
            decision_threshold=self.decision_threshold,
        )

    def _compute_checksum(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def is_ready(self) -> bool:
        return self._session is not None or self._metadata.is_mock

    def get_metadata(self) -> ModelMetadata:
        return self._metadata

    def predict(self, image_input: Any) -> ModelPrediction:
        """
        Executes visual inference on a QR image (PIL Image, bytes, or file path).
        """
        start_time = time.perf_counter()

        # Parse image
        img: Optional[Image.Image] = None
        try:
            if isinstance(image_input, Image.Image):
                img = image_input
            elif isinstance(image_input, (bytes, bytearray)):
                img = Image.open(io.BytesIO(image_input))
            elif isinstance(image_input, str) and os.path.exists(image_input):
                img = Image.open(image_input)
            else:
                return ModelPrediction(
                    model_name=self._metadata.name,
                    model_version=self._metadata.version,
                    status=PredictionStatus.ERROR,
                    prediction=0,
                    probability=None,
                    confidence=0.0,
                    is_mock=self._metadata.is_mock,
                    inference_time_ms=(time.perf_counter() - start_time) * 1000.0,
                    error_reason=f"Unsupported image input: {type(image_input)}",
                )
        except Exception as exc:
            return ModelPrediction(
                model_name=self._metadata.name,
                model_version=self._metadata.version,
                status=PredictionStatus.ERROR,
                prediction=0,
                probability=None,
                confidence=0.0,
                is_mock=self._metadata.is_mock,
                inference_time_ms=(time.perf_counter() - start_time) * 1000.0,
                error_reason=f"Image decoding failed: {exc}",
            )

        # Real ONNX image model execution if session is loaded
        if self._session is not None and not self._metadata.is_mock:
            try:
                import numpy as np
                resized = img.convert("L").resize((224, 224))
                tensor = np.array(resized, dtype=np.float32) / 255.0
                tensor = np.expand_dims(tensor, axis=(0, 1))  # (1, 1, 224, 224)

                input_name = self._session.get_inputs()[0].name
                outputs = self._session.run(None, {input_name: tensor})
                prob = float(outputs[0][0][0])
                pred_class = 1 if prob >= self.decision_threshold else 0
                return ModelPrediction(
                    model_name=self._metadata.name,
                    model_version=self._metadata.version,
                    status=PredictionStatus.SUCCESS,
                    prediction=pred_class,
                    probability=round(prob, 4),
                    confidence=round(prob if pred_class == 1 else 1.0 - prob, 4),
                    is_mock=False,
                    inference_time_ms=(time.perf_counter() - start_time) * 1000.0,
                )
            except Exception as exc:
                return ModelPrediction(
                    model_name=self._metadata.name,
                    model_version=self._metadata.version,
                    status=PredictionStatus.ERROR,
                    prediction=0,
                    probability=None,
                    confidence=0.0,
                    is_mock=False,
                    inference_time_ms=(time.perf_counter() - start_time) * 1000.0,
                    error_reason=f"ONNX image inference error: {exc}",
                )

        # Mock adapter response (Clearly identified)
        return ModelPrediction(
            model_name=self._metadata.name,
            model_version=self._metadata.version,
            status=PredictionStatus.SUCCESS,
            prediction=0,
            probability=0.10,
            confidence=0.90,
            is_mock=True,
            inference_time_ms=(time.perf_counter() - start_time) * 1000.0,
        )

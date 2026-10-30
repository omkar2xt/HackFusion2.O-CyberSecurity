"""
SignalSafe Campus - URL Classification Model Adapter
Module: backend/app/services/detection/model_adapters/url_adapter.py

Adapter for Model A (URL Phishing Classifier).
Consumes authoritative 34-dimensional feature vectors from url_features.py.
Supports ONNX Runtime, joblib, and contract-compliant fallback mocks.
"""

import hashlib
import os
import time
from typing import Any, List, Optional

from backend.app.services.detection.model_adapters.base import (
    BaseModelAdapter,
    ModelMetadata,
    ModelPrediction,
    ModelType,
    PredictionStatus,
)
from backend.app.services.detection.url_features import (
    URL_FEATURE_NAMES,
    URL_FEATURE_SCHEMA_VERSION,
    URLFeatures,
    extract_url_feature_vector,
)

EXPECTED_FEATURE_DIM = len(URL_FEATURE_NAMES)  # Exactly 34 features


class URLModelAdapter(BaseModelAdapter):
    """
    Model adapter for URL phishing classification.
    Validates schema compatibility strictly against URL_FEATURE_SCHEMA_VERSION.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        expected_checksum: Optional[str] = None,
        decision_threshold: float = 0.50,
    ):
        self.model_path = model_path or os.environ.get("URL_MODEL_PATH", "models/url_classifier_v1.onnx")
        self.expected_checksum = expected_checksum
        self.decision_threshold = decision_threshold
        self._session: Any = None
        self._metadata: ModelMetadata = self._initialize_adapter()

    def _initialize_adapter(self) -> ModelMetadata:
        """Attempts to load a verified ONNX or joblib model artifact, falling back to mock."""
        candidates = [
            self.model_path,
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "detection", "url_classifier_best.joblib")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "detection", "url_classifier_best.onnx")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "detection", "url_classifier_best.joblib")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "detection", "url_classifier_best.onnx")),
            os.path.join("SignalSafe_Campus", "models", "production", "url_classifier_best.joblib"),
            os.path.join("SignalSafe_Campus", "models", "production", "url_classifier_best.onnx"),
        ]
        resolved_path = None
        for cand in candidates:
            if cand and os.path.exists(cand):
                resolved_path = cand
                break
        self.model_path = resolved_path or self.model_path

        if self.model_path and os.path.exists(self.model_path):
            try:
                # 1. Verify Checksum if provided
                actual_hash = self._compute_checksum(self.model_path)
                if self.expected_checksum and actual_hash.lower() != self.expected_checksum.lower():
                    print(f"[SECURITY ALERT] Model artifact checksum mismatch for {self.model_path}")
                    return self._create_mock_metadata(f"Checksum mismatch: expected {self.expected_checksum}")

                # 2. Attempt ONNX Runtime load
                if self.model_path.endswith(".onnx"):
                    import onnxruntime as ort
                    self._session = ort.InferenceSession(
                        self.model_path,
                        providers=["CPUExecutionProvider"],
                    )
                    return ModelMetadata(
                        name="URLClassifier-ONNX",
                        version="1.0.0",
                        model_type=ModelType.ONNX,
                        feature_schema_version=URL_FEATURE_SCHEMA_VERSION,
                        artifact_path=self.model_path,
                        sha256_checksum=actual_hash,
                        is_mock=False,
                        calibrated_probabilities=True,
                        decision_threshold=self.decision_threshold,
                    )

                # 3. Attempt joblib load
                if self.model_path.endswith((".pkl", ".joblib")):
                    import joblib
                    self._session = joblib.load(self.model_path)
                    return ModelMetadata(
                        name="URLClassifier-Joblib",
                        version="1.0.0",
                        model_type=ModelType.JOBLIB,
                        feature_schema_version=URL_FEATURE_SCHEMA_VERSION,
                        artifact_path=self.model_path,
                        sha256_checksum=actual_hash,
                        is_mock=False,
                        calibrated_probabilities=hasattr(self._session, "predict_proba"),
                        decision_threshold=self.decision_threshold,
                    )
            except Exception as exc:
                print(f"[WARN] Failed to load model artifact at {self.model_path}: {exc}")
                return self._create_mock_metadata(f"Artifact load failure: {exc}")

        # Artifact not present; operate in contract-compliant mock adapter mode
        return self._create_mock_metadata("Artifact not yet deployed (independent training in progress)")

    def _create_mock_metadata(self, note: str) -> ModelMetadata:
        return ModelMetadata(
            name="URLClassifier-MockAdapter",
            version="1.0.0-mock",
            model_type=ModelType.MOCK,
            feature_schema_version=URL_FEATURE_SCHEMA_VERSION,
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

    def predict(self, features: Any) -> ModelPrediction:
        """
        Executes prediction on input features.
        Accepts: URLFeatures instance, flat float list, or raw URL string.
        """
        start_time = time.perf_counter()

        # 1. Normalize feature vector input
        if isinstance(features, URLFeatures):
            feature_vec = features.to_vector()
        elif isinstance(features, list):
            feature_vec = [float(x) for x in features]
        elif isinstance(features, str):
            feature_vec = extract_url_feature_vector(features)
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
                error_reason=f"Unsupported feature input type: {type(features)}",
            )

        # 2. Schema Compatibility Verification
        if len(feature_vec) != EXPECTED_FEATURE_DIM:
            return ModelPrediction(
                model_name=self._metadata.name,
                model_version=self._metadata.version,
                status=PredictionStatus.SCHEMA_MISMATCH,
                prediction=0,
                probability=None,
                confidence=0.0,
                is_mock=self._metadata.is_mock,
                inference_time_ms=(time.perf_counter() - start_time) * 1000.0,
                error_reason=(
                    f"Feature dimension mismatch: expected {EXPECTED_FEATURE_DIM} "
                    f"features for schema {URL_FEATURE_SCHEMA_VERSION}, got {len(feature_vec)}"
                ),
            )

        # 3. Inference Execution (Real ONNX / Joblib)
        if self._session is not None and not self._metadata.is_mock:
            try:
                import numpy as np
                x = np.array([feature_vec], dtype=np.float32)

                if self._metadata.model_type == ModelType.ONNX:
                    input_name = self._session.get_inputs()[0].name
                    outputs = self._session.run(None, {input_name: x})
                    raw_pred = outputs[0]
                    # Check for probability tensor in output
                    if len(outputs) > 1 and isinstance(outputs[1], list):
                        # Dictionary output for probabilities
                        prob_phish = float(outputs[1][0].get(1, 0.5))
                    elif len(raw_pred.shape) > 1 and raw_pred.shape[1] > 1:
                        prob_phish = float(raw_pred[0][1])
                    else:
                        prob_phish = float(raw_pred[0])

                    pred_class = 1 if prob_phish >= self.decision_threshold else 0
                    conf = prob_phish if pred_class == 1 else (1.0 - prob_phish)
                    return ModelPrediction(
                        model_name=self._metadata.name,
                        model_version=self._metadata.version,
                        status=PredictionStatus.SUCCESS,
                        prediction=pred_class,
                        probability=round(prob_phish, 4),
                        confidence=round(conf, 4),
                        is_mock=False,
                        inference_time_ms=(time.perf_counter() - start_time) * 1000.0,
                    )

                elif self._metadata.model_type == ModelType.JOBLIB:
                    raw_pred = self._session.predict(x)[0]
                    prob_phish = None
                    if hasattr(self._session, "predict_proba"):
                        probs = self._session.predict_proba(x)[0]
                        prob_phish = float(probs[1])
                    pred_class = int(raw_pred)
                    conf = prob_phish if prob_phish is not None else 0.75
                    return ModelPrediction(
                        model_name=self._metadata.name,
                        model_version=self._metadata.version,
                        status=PredictionStatus.SUCCESS,
                        prediction=pred_class,
                        probability=round(prob_phish, 4) if prob_phish is not None else None,
                        confidence=round(conf, 4),
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
                    error_reason=f"Inference runtime error: {str(exc)}",
                )

        # 4. Mock Adapter Execution (Clearly identified, non-fabricated)
        # Calculates an illustrative heuristic score based on feature vector values
        # without claiming to be an actual trained model.
        # Feature indices: 18: is_ip_address, 23: is_punycode, 30: suspicious_file_extension, 31: suspicious_keyword_count
        is_ip = feature_vec[18] > 0
        is_puny = feature_vec[23] > 0
        has_ext = feature_vec[30] > 0
        kw_count = feature_vec[31]

        mock_phish_score = 0.10
        if is_ip:
            mock_phish_score += 0.35
        if is_puny:
            mock_phish_score += 0.30
        if has_ext:
            mock_phish_score += 0.25
        if kw_count > 0:
            mock_phish_score += min(kw_count * 0.10, 0.30)

        mock_phish_score = min(round(mock_phish_score, 4), 0.95)
        pred_class = 1 if mock_phish_score >= self.decision_threshold else 0
        conf = mock_phish_score if pred_class == 1 else round(1.0 - mock_phish_score, 4)

        return ModelPrediction(
            model_name=self._metadata.name,
            model_version=self._metadata.version,
            status=PredictionStatus.SUCCESS,
            prediction=pred_class,
            probability=mock_phish_score,
            confidence=conf,
            is_mock=True,
            inference_time_ms=(time.perf_counter() - start_time) * 1000.0,
        )

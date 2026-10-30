"""
SignalSafe Campus - QR Image & Payload Analysis Engine
Module: backend/app/services/detection/qr/analyzer.py

Validates QR image constraints, decodes visual QR codes, extracts destinations,
routes URLs through the authoritative 34-feature extraction pipeline, and handles
non-URL payloads while keeping image classification decoupled from URL analysis.
"""

from dataclasses import dataclass, field
import io
import re
from typing import Any, Dict, List, Optional, Tuple
try:
    from PIL import Image
except ImportError:
    Image = None

try:
    import zxingcpp
except ImportError:
    zxingcpp = None

from backend.app.core.errors import ValidationException
from backend.app.services.detection.model_adapters.qr_adapter import QRModelAdapter
from backend.app.services.detection.model_adapters.base import ModelPrediction
from backend.app.services.detection.url_features import (
    URLNormalizationResult,
    normalize_url,
)

# Limits to prevent resource exhaustion / decompression bombs
MAX_IMAGE_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MIN_IMAGE_DIMENSION = 32  # 32x32 px
MAX_IMAGE_DIMENSION = 4096  # 4096x4096 px
PERMITTED_IMAGE_FORMATS = frozenset({"PNG", "JPEG", "JPG", "WEBP", "BMP", "GIF"})

URL_PATTERN = re.compile(
    r"^(?:https?://|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/|$))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DecodedQREntry:
    """Represents a single decoded barcode/QR symbol extracted from an image."""
    raw_content: str
    format_name: str
    is_url: bool
    payload_type: str  # URL, WIFI, SMSTO, TEL, MAILTO, VCARD, RAW_TEXT
    normalized_url: Optional[str] = None
    url_normalization: Optional[URLNormalizationResult] = None


@dataclass(frozen=True)
class QRAnalysisResult:
    """Consolidated outcome of QR image and payload analysis."""
    is_valid_image: bool
    error_reason: Optional[str]
    image_format: Optional[str]
    dimensions: Optional[Tuple[int, int]]
    file_size_bytes: int
    codes_found: int
    entries: List[DecodedQREntry]
    visual_model_prediction: Optional[ModelPrediction] = None
    has_multiple_codes: bool = False


class QRAnalyzer:
    """Analyzer for QR images and decoded payloads."""

    def __init__(self, qr_model_adapter: Optional[QRModelAdapter] = None):
        self.qr_model_adapter = qr_model_adapter or QRModelAdapter()

    def validate_image_bytes(self, image_bytes: bytes) -> Tuple[Image.Image, str, Tuple[int, int]]:
        """
        Strictly validates image byte length, format, and dimensions.
        Guards against decompression bombs and malicious malformed graphics.
        """
        if not image_bytes:
            raise ValidationException("QR image data is empty.")

        file_size = len(image_bytes)
        if file_size > MAX_IMAGE_FILE_SIZE_BYTES:
            raise ValidationException(
                f"QR image file size ({file_size} bytes) exceeds limit of {MAX_IMAGE_FILE_SIZE_BYTES} bytes."
            )

        try:
            img = Image.open(io.BytesIO(image_bytes))
        except Exception as exc:
            raise ValidationException(f"Invalid or corrupted image format: {str(exc)}")

        img_format = (img.format or "").upper()
        if img_format not in PERMITTED_IMAGE_FORMATS:
            raise ValidationException(
                f"Unsupported image format '{img_format}'. Supported formats: {sorted(list(PERMITTED_IMAGE_FORMATS))}"
            )

        w, h = img.size
        if w < MIN_IMAGE_DIMENSION or h < MIN_IMAGE_DIMENSION:
            raise ValidationException(
                f"Image dimensions ({w}x{h}) below minimum permitted threshold ({MIN_IMAGE_DIMENSION}x{MIN_IMAGE_DIMENSION})."
            )

        if w > MAX_IMAGE_DIMENSION or h > MAX_IMAGE_DIMENSION:
            raise ValidationException(
                f"Image dimensions ({w}x{h}) exceed maximum permitted threshold ({MAX_IMAGE_DIMENSION}x{MAX_IMAGE_DIMENSION})."
            )

        return img, img_format, (w, h)

    def classify_payload_type(self, text: str) -> Tuple[str, bool]:
        """
        Categorizes QR payload type.
        Returns (payload_type, is_url).
        """
        clean = text.strip()
        upper = clean.upper()

        if upper.startswith("WIFI:"):
            return ("WIFI", False)
        if upper.startswith("SMSTO:") or upper.startswith("SMS:"):
            return ("SMSTO", False)
        if upper.startswith("TEL:"):
            return ("TEL", False)
        if upper.startswith("MAILTO:"):
            return ("MAILTO", False)
        if upper.startswith("BEGIN:VCARD"):
            return ("VCARD", False)

        # Check if standard URL
        if clean.startswith(("http://", "https://")) or URL_PATTERN.match(clean):
            return ("URL", True)

        return ("RAW_TEXT", False)

    def analyze_decoded_text(self, text: str) -> DecodedQREntry:
        """Parses a decoded QR content string without image processing."""
        payload_type, is_url = self.classify_payload_type(text)
        normalized_url = None
        norm_result = None

        if is_url:
            norm_result = normalize_url(text)
            if norm_result.is_valid:
                normalized_url = norm_result.normalized_url

        return DecodedQREntry(
            raw_content=text,
            format_name="QR_CODE",
            is_url=is_url,
            payload_type=payload_type,
            normalized_url=normalized_url,
            url_normalization=norm_result,
        )

    def analyze_qr_image(self, image_bytes: bytes) -> QRAnalysisResult:
        """
        Performs full end-to-end QR image analysis:
        1. Validates image envelope (size, format, dimensions).
        2. Visual ML inference via QRModelAdapter (Model B).
        3. Decodes all 2D barcodes present using zxing-cpp.
        4. Classifies payloads and prepares URLs for authoritative pipeline inspection.
        """
        try:
            img, img_format, dims = self.validate_image_bytes(image_bytes)
        except ValidationException as val_err:
            return QRAnalysisResult(
                is_valid_image=False,
                error_reason=val_err.message,
                image_format=None,
                dimensions=None,
                file_size_bytes=len(image_bytes),
                codes_found=0,
                entries=[],
                visual_model_prediction=None,
            )

        # Visual model inference (Model B)
        visual_pred = self.qr_model_adapter.predict(img)

        # Barcode / QR decoding via zxing-cpp
        try:
            barcodes = zxingcpp.read_barcodes(img)
        except Exception as exc:
            barcodes = []

        entries: List[DecodedQREntry] = []
        for bc in barcodes:
            raw_txt = bc.text
            payload_type, is_url = self.classify_payload_type(raw_txt)
            norm_result = None
            norm_url = None
            if is_url:
                norm_result = normalize_url(raw_txt)
                if norm_result.is_valid:
                    norm_url = norm_result.normalized_url

            entries.append(
                DecodedQREntry(
                    raw_content=raw_txt,
                    format_name=str(bc.format),
                    is_url=is_url,
                    payload_type=payload_type,
                    normalized_url=norm_url,
                    url_normalization=norm_result,
                )
            )

        return QRAnalysisResult(
            is_valid_image=True,
            error_reason=None,
            image_format=img_format,
            dimensions=dims,
            file_size_bytes=len(image_bytes),
            codes_found=len(entries),
            entries=entries,
            visual_model_prediction=visual_pred,
            has_multiple_codes=(len(entries) > 1),
        )


qr_analyzer = QRAnalyzer()

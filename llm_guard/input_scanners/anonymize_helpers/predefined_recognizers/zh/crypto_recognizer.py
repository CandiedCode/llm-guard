from __future__ import annotations

from typing import ClassVar

from presidio_analyzer import Pattern
from presidio_analyzer.predefined_recognizers import CryptoRecognizer as PresidioCryptoRecognizer


class CryptoRecognizer(PresidioCryptoRecognizer):
    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern("Crypto (Medium)", r"[13][a-km-zA-HJ-NP-Z1-9]{26,33}", 0.5),
    ]

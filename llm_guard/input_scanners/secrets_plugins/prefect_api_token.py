"""
This plugin searches for Prefect API Tokens.
"""

from __future__ import annotations

import re

from detect_secrets.plugins.base import RegexBasedDetector


class PrefectApiTokenDetector(RegexBasedDetector):
    """Scans for Prefect API Tokens."""

    @property
    def secret_type(self) -> str:
        return "Prefect API Token"

    @property
    def denylist(self) -> list[re.Pattern]:
        return [re.compile(r"""(?i)\b(pnu_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60|;]|$)""")]

"""
This plugin searches for Finnhub Access Tokens.
"""

from __future__ import annotations

import re

from detect_secrets.plugins.base import RegexBasedDetector


class FinnhubAccessTokenDetector(RegexBasedDetector):
    """Scans for Finnhub Access Tokens."""

    @property
    def secret_type(self) -> str:
        return "Finnhub Access Token"

    @property
    def denylist(self) -> list[re.Pattern]:
        return [
            # Finnhub Access Token
            re.compile(
                r"""(?i)(?:finnhub)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)"""
            ),
        ]

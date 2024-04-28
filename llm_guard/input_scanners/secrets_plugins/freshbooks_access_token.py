"""
This plugin searches for Freshbooks Access Tokens.
"""

from __future__ import annotations

import re

from detect_secrets.plugins.base import RegexBasedDetector


class FreshbooksAccessTokenDetector(RegexBasedDetector):
    """Scans for Freshbooks Access Tokens."""

    @property
    def secret_type(self) -> str:
        return "Freshbooks Access Token"

    @property
    def denylist(self) -> list[re.Pattern]:
        return [
            # Freshbooks Access Token
            re.compile(
                r"""(?i)(?:freshbooks)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)"""
            ),
        ]

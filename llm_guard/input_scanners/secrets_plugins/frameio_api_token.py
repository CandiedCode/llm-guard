"""
This plugin searches for Frame.io API tokens.
"""

from __future__ import annotations

import re

from detect_secrets.plugins.base import RegexBasedDetector


class FrameIoApiTokenDetector(RegexBasedDetector):
    """Scans for Frame.io API Tokens."""

    @property
    def secret_type(self) -> str:
        return "Frame.io API Token"

    @property
    def denylist(self) -> list[re.Pattern]:
        return [
            # Frame.io API token
            re.compile(r"""(?i)fio-u-[a-z0-9\-_=]{64}"""),
        ]

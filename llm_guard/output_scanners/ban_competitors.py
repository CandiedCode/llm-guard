from __future__ import annotations

from typing import Sequence

from llm_guard.input_scanners.ban_competitors import BanCompetitors as InputBanCompetitors
from llm_guard.model import Model

from .base import Scanner


class BanCompetitors(Scanner):
    """
    Scanner that detects if an output contains a competitor.

    It uses a named-entity recognition model to extract organization and match it against a list of competitors.
    """

    def __init__(
        self,
        competitors: Sequence[str],
        *,
        threshold: float = 0.5,
        redact: bool = True,
        model: Model | None = None,
    ) -> None:
        """
        Initializes BanCompetitors object.

        Parameters:
            competitors (Sequence[str]): List of competitors to ban.
            threshold (float, optional): Threshold to determine if an organization is present in the output. Default is 0.5.
            redact (bool, optional): Whether to redact the organization name. Default is True.
            model (Model, optional): Model to use for named-entity recognition. Default is BASE model.

        Raises:
            ValueError: If no competitors are provided.
        """
        self._scanner = InputBanCompetitors(
            competitors,
            threshold=threshold,
            redact=redact,
            model=model,
        )

    def scan(self, prompt: str, output: str) -> tuple[str, bool, float]:
        return self._scanner.scan(output)

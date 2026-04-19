"""Prompt and decision logger — appends per-request JSONL lines to disk."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config import SETTINGS

logger = logging.getLogger(__name__)


def log_event(category: str, payload: dict[str, Any]) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "category": category,
        **payload,
    }
    path: Path = SETTINGS.audit_log_path / "prompts.jsonl"
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except OSError as exc:
        logger.warning("prompt log write failed: %s", exc)

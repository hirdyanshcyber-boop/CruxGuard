"""Centralised configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    google_api_key: str
    abuseipdb_api_key: str
    gemma_model: str
    gemma_temperature: float
    audit_log_path: Path
    aws_region: str


def load_settings() -> Settings:
    audit_path = Path(os.getenv("AUDIT_LOG_PATH", "./audit")).resolve()
    audit_path.mkdir(parents=True, exist_ok=True)

    return Settings(
        google_api_key=os.getenv("GOOGLE_API_KEY", ""),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
        gemma_model=os.getenv("GEMMA_MODEL", "gemma-4-31b-it"),
        gemma_temperature=float(os.getenv("GEMMA_TEMPERATURE", "0.3")),
        audit_log_path=audit_path,
        aws_region=os.getenv("AWS_REGION", "ap-southeast-2"),
    )


SETTINGS = load_settings()

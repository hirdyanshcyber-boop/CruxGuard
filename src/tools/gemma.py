"""Gemma 4 client via Google AI Studio (google-genai SDK).

Wraps the new `google-genai` package with a JSON-only response channel so
agents can parse structured verdicts without brittle regex on free-form
text. Falls back to a deterministic stub when the API key is missing or
the call fails, so the graph stays runnable offline.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from google import genai
from google.genai import types

from src.config import SETTINGS

logger = logging.getLogger(__name__)

_client: genai.Client | None = None


def _get_client() -> genai.Client:
    global _client
    if _client is not None:
        return _client
    if not SETTINGS.google_api_key:
        raise RuntimeError("GOOGLE_API_KEY not set — cannot call Gemma 4.")
    _client = genai.Client(api_key=SETTINGS.google_api_key)
    return _client


def _extract_json(text: str) -> dict[str, Any]:
    """Tolerant JSON extraction — handles bare objects and fenced blocks."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group(0))
    raise ValueError(f"no JSON object found in model reply: {text[:200]!r}")


def ask_gemma_json(
    system_prompt: str,
    user_prompt: str,
    *,
    temperature: float | None = None,
    schema_hint: str = "",
) -> dict[str, Any]:
    """Send a prompt to Gemma 4 and parse a JSON object from the reply."""
    try:
        client = _get_client()
    except RuntimeError as exc:
        logger.warning("Gemma offline stub engaged: %s", exc)
        return {"decision": "review", "confidence": 0.0, "rationale": str(exc)}

    prompt = user_prompt
    if schema_hint:
        prompt = f"{user_prompt}\n\nReturn ONLY a JSON object matching: {schema_hint}"

    try:
        response = client.models.generate_content(
            model=SETTINGS.gemma_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=temperature if temperature is not None else SETTINGS.gemma_temperature,
                response_mime_type="application/json",
            ),
        )
        return _extract_json(response.text or "")
    except Exception as exc:  # noqa: BLE001 — offline resilience for dev
        logger.warning("Gemma call failed, returning review stub: %s", exc)
        return {"decision": "review", "confidence": 0.0, "rationale": f"gemma_error: {exc}"}

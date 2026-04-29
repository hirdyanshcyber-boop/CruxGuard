"""ContextSanitiserAgent — deterministic pre-LLM prompt-injection firewall.

Runs immediately after WorkflowManager, before the IP validator and any
LLM calls. Uses pure regex so it cannot itself be confused by adversarial
text. If injection patterns are found the payload is scrubbed and
`injection_detected` is set on state, which causes PolicyEnforcer to
force-deny regardless of what the LLM concludes.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any

from src.state import AgentFinding, ReviewState
from src.tools.prompt_logger import log_event

# Patterns that indicate an attempt to subvert the pipeline.
# Order matters: more specific patterns first.
_INJECTION_PATTERNS: list[re.Pattern[str]] = [re.compile(p, re.IGNORECASE) for p in [
    r"ignore\s+(previous|prior|above|all)\s+instructions?",
    r"\bSYSTEM\s*[:：]\s*new\s+policy",
    r"\bSYSTEM\s*[:：]",
    r"disregard\s+(the|your|all)\s+rules?",
    r"\b(you are now|act as|pretend you are|roleplay as|DAN\b)",
    r"decision\s*=\s*(benign|allow)",
    r"output\s+only\s*[:\-]?\s*\{",          # force JSON output attack
    r"\[admin\s*override\]",
    r"return\s+allow",
    r"I\s+am\s+(the\s+)?(admin|ciso|administrator|root|superuser)",
    r"think\s+I\s+am\s+(admin|superuser|root)",
    r"give\s+me\s+(access|all\s+permissions?|admin)",
    r"bypass\s+(security|analysis|this|all)",
    r"stop[_ ]analysis",
    r"escalate[_ ]to[_ ]allow",
    r"approved[_ ]by[_ ]\w+[_ ]soc",          # fake upstream approval
    r"do\s+not\s+re[-\s]?evaluate",
    r"false\s+positive\s*[,\-]\s*(please\s+)?allow",
    r"whitelist(ed)?\s+this\s+ip",
    r"history\s+shows.*benign",
    r"maintain\s+pattern",
]]

_REDACT = "[REDACTED-INJECTION]"


def _scan_value(value: Any) -> tuple[Any, bool]:
    """Return (sanitised_value, was_dirty)."""
    if isinstance(value, str):
        dirty = False
        for pat in _INJECTION_PATTERNS:
            if pat.search(value):
                dirty = True
                value = pat.sub(_REDACT, value)
        return value, dirty
    if isinstance(value, dict):
        result, dirty = {}, False
        for k, v in value.items():
            clean_v, v_dirty = _scan_value(v)
            result[k] = clean_v
            dirty = dirty or v_dirty
        return result, dirty
    if isinstance(value, list):
        result_list, dirty = [], False
        for item in value:
            clean_item, item_dirty = _scan_value(item)
            result_list.append(clean_item)
            dirty = dirty or item_dirty
        return result_list, dirty
    return value, False


def context_sanitiser_node(state: ReviewState) -> ReviewState:
    start = time.perf_counter()
    raw_context: dict[str, Any] = state.get("context", {})

    clean_context, injection_found = _scan_value(raw_context)
    state["context"] = clean_context
    state["injection_detected"] = injection_found

    if injection_found and state.get("verdict") != "deny":
        state["verdict"] = "deny"
        state["halt_reason"] = "prompt_injection_detected"

    finding: AgentFinding = {
        "agent": "ContextSanitiserAgent",
        "decision": "injection_detected" if injection_found else "clean",
        "confidence": 1.0,
        "rationale": (
            "Prompt-injection pattern(s) found in context; payload scrubbed and request auto-denied."
            if injection_found
            else "Context passed injection scan."
        ),
        "evidence": {
            "injection_detected": injection_found,
            "patterns_checked": len(_INJECTION_PATTERNS),
            "sanitised_context": clean_context,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "latency_ms": (time.perf_counter() - start) * 1000,
    }
    state["findings"].append(finding)
    log_event("context_sanitiser", {"correlation_id": state["correlation_id"], **finding})
    return state

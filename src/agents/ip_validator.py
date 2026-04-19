"""IPValidatorAgent — deterministic format/regex + AbuseIPDB reputation pull."""

from __future__ import annotations

import ipaddress
import time
from datetime import datetime, timezone

from src.state import AgentFinding, ReviewState
from src.tools.abuseipdb import check_ip
from src.tools.prompt_logger import log_event


def _is_valid(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def ip_validator_node(state: ReviewState) -> ReviewState:
    start = time.perf_counter()
    ip = state.get("ip_address", "")
    valid = _is_valid(ip)

    evidence: dict = {"format_valid": valid}
    if valid:
        evidence["reputation"] = check_ip(ip)

    finding: AgentFinding = {
        "agent": "IPValidatorAgent",
        "decision": "valid" if valid else "invalid",
        "confidence": 1.0 if valid else 0.0,
        "rationale": "IP parseable" if valid else "IP failed RFC 791/4291 parse",
        "evidence": evidence,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "latency_ms": (time.perf_counter() - start) * 1000,
    }

    state["findings"].append(finding)
    state["ip_valid"] = valid
    if not valid:
        state["halt_reason"] = "invalid_ip_format"
        state["verdict"] = "deny"

    log_event("ip_validator", {"correlation_id": state["correlation_id"], **finding})
    return state

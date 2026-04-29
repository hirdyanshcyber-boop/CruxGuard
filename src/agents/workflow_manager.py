"""WorkflowManager — entry node. Normalises input, validates role, seeds trust score."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from src.state import AgentFinding, ReviewState

# Roles that may legitimately arrive on the wire.
# Anything not in this set is clamped to "guest" — callers must be
# authenticated before a privileged role is trusted.
_VALID_ROLES: frozenset[str] = frozenset({
    "analyst", "engineer", "auditor", "admin", "guest"
})

# High-privilege roles that warrant an extra warning in findings so that
# operators can spot unexpected escalation attempts in the audit log.
_PRIVILEGED_ROLES: frozenset[str] = frozenset({"admin", "engineer"})


def workflow_manager_node(state: ReviewState) -> ReviewState:
    start = time.perf_counter()

    claimed_role: str = state.get("role", "guest") or "guest"
    if claimed_role not in _VALID_ROLES:
        # Unknown role — treat as unauthenticated guest.
        state["role"] = "guest"
        role_note = f"unknown role '{claimed_role}' clamped to guest"
    else:
        role_note = f"role '{claimed_role}' accepted"

    state.setdefault("action", "network.ingress")
    state.setdefault("context", {})
    state.setdefault("findings", [])
    state.setdefault("verdict", "review")
    state.setdefault("trust_score", 1.0)

    privileged_flag = state["role"] in _PRIVILEGED_ROLES

    finding: AgentFinding = {
        "agent": "WorkflowManager",
        "decision": "accepted",
        "confidence": 1.0,
        "rationale": f"request normalised and admitted to review graph; {role_note}",
        "evidence": {
            "correlation_id": state.get("correlation_id"),
            "claimed_role": claimed_role,
            "effective_role": state["role"],
            "privileged_role_flag": privileged_flag,
            "action": state["action"],
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "latency_ms": (time.perf_counter() - start) * 1000,
    }
    state["findings"].append(finding)
    return state

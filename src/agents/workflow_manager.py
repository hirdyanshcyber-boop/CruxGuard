"""WorkflowManager — entry node. Normalises input and seeds trust score."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from src.state import AgentFinding, ReviewState


def workflow_manager_node(state: ReviewState) -> ReviewState:
    start = time.perf_counter()

    state.setdefault("role", "guest")
    state.setdefault("action", "network.ingress")
    state.setdefault("context", {})
    state.setdefault("findings", [])
    state.setdefault("verdict", "review")
    state.setdefault("trust_score", 1.0)

    finding: AgentFinding = {
        "agent": "WorkflowManager",
        "decision": "accepted",
        "confidence": 1.0,
        "rationale": "request normalised and admitted to review graph",
        "evidence": {
            "correlation_id": state.get("correlation_id"),
            "role": state["role"],
            "action": state["action"],
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "latency_ms": (time.perf_counter() - start) * 1000,
    }
    state["findings"].append(finding)
    return state

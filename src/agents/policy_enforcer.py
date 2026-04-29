"""PolicyEnforcerAgent — RBAC + ABAC policy evaluation (least-privilege ZTA)."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from src.state import AgentFinding, ReviewState

_ROLE_MATRIX: dict[str, set[str]] = {
    "analyst": {"network.ingress", "log.read"},
    "engineer": {"network.ingress", "network.egress", "firewall.update", "log.read"},
    "auditor": {"log.read", "audit.export"},
    "admin": {"network.ingress", "network.egress", "firewall.update", "log.read", "audit.export", "policy.write"},
    "guest": set(),
}


def _severity_allows(severity: str) -> bool:
    return severity in {"low", "medium"}


def policy_enforcer_node(state: ReviewState) -> ReviewState:
    start = time.perf_counter()
    role = state.get("role", "guest")
    action = state.get("action", "")
    severity = state.get("severity", "low")
    injection_detected = state.get("injection_detected", False)

    # Injection detected upstream means the request is adversarial — deny
    # unconditionally regardless of role or severity. RBAC/ABAC checks are
    # still evaluated for the audit record but cannot override this.
    if injection_detected:
        state["verdict"] = "deny"
        rationale = (
            f"AUTO-DENY: prompt injection detected upstream. "
            f"role={role} action={action} severity={severity}"
        )
        finding: AgentFinding = {
            "agent": "PolicyEnforcerAgent",
            "decision": "deny",
            "confidence": 1.0,
            "rationale": rationale,
            "evidence": {
                "injection_detected": True,
                "rbac_ok": None,
                "abac_ok": None,
                "permitted_actions": sorted(_ROLE_MATRIX.get(role, set())),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "latency_ms": (time.perf_counter() - start) * 1000,
        }
        state["findings"].append(finding)
        return state

    permitted_actions = _ROLE_MATRIX.get(role, set())
    rbac_ok = action in permitted_actions
    abac_ok = _severity_allows(severity)

    if rbac_ok and abac_ok and state.get("verdict") == "review":
        state["verdict"] = "allow"
    elif not rbac_ok:
        state["verdict"] = "deny"
    elif not abac_ok and state.get("verdict") == "review":
        state["verdict"] = "quarantine"

    rationale = (
        f"role={role} action={action} rbac_ok={rbac_ok} "
        f"severity={severity} abac_ok={abac_ok}"
    )

    finding: AgentFinding = {
        "agent": "PolicyEnforcerAgent",
        "decision": state["verdict"],
        "confidence": 1.0,
        "rationale": rationale,
        "evidence": {"rbac_ok": rbac_ok, "abac_ok": abac_ok, "permitted_actions": sorted(permitted_actions)},
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "latency_ms": (time.perf_counter() - start) * 1000,
    }
    state["findings"].append(finding)
    return state

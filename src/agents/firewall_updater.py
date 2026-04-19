"""FirewallUpdaterAgent — renders a UFW command reflecting the final verdict.

The command is emitted but NEVER executed here — downstream pipelines apply
it under operator review. Rendering only keeps the agent deterministic and
test-friendly.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from src.state import AgentFinding, ReviewState


def _render_command(verdict: str, ip: str) -> str:
    if verdict == "allow":
        return f"ufw allow from {ip}"
    if verdict == "deny":
        return f"ufw deny from {ip}"
    if verdict == "quarantine":
        return f"ufw limit from {ip} comment 'cruxguard-quarantine'"
    return f"# review required for {ip}"


def firewall_updater_node(state: ReviewState) -> ReviewState:
    start = time.perf_counter()
    cmd = _render_command(state.get("verdict", "review"), state["ip_address"])
    state["firewall_command"] = cmd

    finding: AgentFinding = {
        "agent": "FirewallUpdaterAgent",
        "decision": state.get("verdict", "review"),
        "confidence": 1.0,
        "rationale": "rendered ufw rule (not executed)",
        "evidence": {"command": cmd},
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "latency_ms": (time.perf_counter() - start) * 1000,
    }
    state["findings"].append(finding)
    return state

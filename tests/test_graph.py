"""Smoke tests for the CruxGuard review graph.

These run fully offline — the Gemma client falls back to a deterministic
stub when GOOGLE_API_KEY is absent, and AbuseIPDB falls back similarly.
"""

from __future__ import annotations

from src.graph import GRAPH
from src.state import new_state


def test_invalid_ip_short_circuits_to_audit() -> None:
    state = new_state(ip_address="not.an.ip")
    final = GRAPH.invoke(state)

    assert final["verdict"] == "deny"
    assert final["halt_reason"] == "invalid_ip_format"
    agents_visited = [f["agent"] for f in final["findings"]]
    assert "ThreatAnalyserAgent" not in agents_visited
    assert "AuditLogger" in agents_visited


def test_valid_ip_traverses_full_graph() -> None:
    state = new_state(ip_address="8.8.8.8", role="engineer", action="network.ingress")
    final = GRAPH.invoke(state)

    agents_visited = [f["agent"] for f in final["findings"]]
    for expected in [
        "WorkflowManager",
        "IPValidatorAgent",
        "ThreatAnalyserAgent",
        "PolicyEnforcerAgent",
        "FirewallUpdaterAgent",
        "AuditLogger",
    ]:
        assert expected in agents_visited, f"missing node: {expected}"

    assert final["firewall_command"] is not None


def test_guest_role_is_denied_for_privileged_action() -> None:
    state = new_state(ip_address="1.1.1.1", role="guest", action="firewall.update")
    final = GRAPH.invoke(state)
    assert final["verdict"] == "deny"

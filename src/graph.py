"""CruxGuard review graph.

Compiles a LangGraph StateGraph wiring the six agents plus the audit
logger. ContextSanitiser runs first (deterministic, no LLM) and can
short-circuit straight to audit_logger if injection is detected.

Topology:

    workflow_manager
        │
        ▼
    context_sanitiser ─── injection ───┐
        │ clean                        │
        ▼                              │
    ip_validator ─── invalid ──────────┤
        │ valid                        │
        ▼                              │
    threat_analyser                    │
        │                              │
        ▼                              │
    policy_enforcer                    │
        │                              │
        ▼                              │
    firewall_updater                   │
        │                              │
        └──────► audit_logger ◄────────┘
                    │
                    ▼
                   END
"""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, StateGraph

from src.agents.context_sanitiser import context_sanitiser_node
from src.agents.firewall_updater import firewall_updater_node
from src.agents.ip_validator import ip_validator_node
from src.agents.policy_enforcer import policy_enforcer_node
from src.agents.threat_analyser import threat_analyser_node
from src.agents.workflow_manager import workflow_manager_node
from src.compliance.audit_logger import audit_logger_node
from src.state import ReviewState


def _route_after_sanitise(state: ReviewState) -> Literal["ip_validator", "audit_logger"]:
    return "audit_logger" if state.get("injection_detected") else "ip_validator"


def _route_after_validation(state: ReviewState) -> Literal["threat_analyser", "audit_logger"]:
    return "threat_analyser" if state.get("ip_valid") else "audit_logger"


def build_graph():
    builder = StateGraph(ReviewState)

    builder.add_node("workflow_manager", workflow_manager_node)
    builder.add_node("context_sanitiser", context_sanitiser_node)
    builder.add_node("ip_validator", ip_validator_node)
    builder.add_node("threat_analyser", threat_analyser_node)
    builder.add_node("policy_enforcer", policy_enforcer_node)
    builder.add_node("firewall_updater", firewall_updater_node)
    builder.add_node("audit_logger", audit_logger_node)

    builder.set_entry_point("workflow_manager")
    builder.add_edge("workflow_manager", "context_sanitiser")
    builder.add_conditional_edges(
        "context_sanitiser",
        _route_after_sanitise,
        {"ip_validator": "ip_validator", "audit_logger": "audit_logger"},
    )
    builder.add_conditional_edges(
        "ip_validator",
        _route_after_validation,
        {"threat_analyser": "threat_analyser", "audit_logger": "audit_logger"},
    )
    builder.add_edge("threat_analyser", "policy_enforcer")
    builder.add_edge("policy_enforcer", "firewall_updater")
    builder.add_edge("firewall_updater", "audit_logger")
    builder.add_edge("audit_logger", END)

    return builder.compile()


GRAPH = build_graph()

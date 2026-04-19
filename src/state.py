"""Shared state object passed between nodes in the review graph.

The graph is a finite-state workflow: every node reads the current state,
appends its findings, and returns the mutated state. The audit logger at
the tail of the graph serialises the whole state for APRA evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal, TypedDict
from uuid import uuid4

from langgraph.graph.message import add_messages

Verdict = Literal["allow", "deny", "quarantine", "review"]
Severity = Literal["low", "medium", "high", "critical"]


class AgentFinding(TypedDict, total=False):
    agent: str
    decision: str
    confidence: float
    rationale: str
    evidence: dict[str, Any]
    timestamp: str
    latency_ms: float


class ReviewState(TypedDict, total=False):
    # --- request identity ---
    correlation_id: str
    submitted_at: str

    # --- request payload ---
    ip_address: str
    role: str
    action: str
    context: dict[str, Any]

    # --- per-agent findings (append-only) ---
    findings: list[AgentFinding]

    # --- aggregate decision ---
    verdict: Verdict
    severity: Severity
    trust_score: float
    firewall_command: str | None

    # --- control flow flags ---
    ip_valid: bool
    halt_reason: str | None

    # --- LLM transcript for audit ---
    messages: Annotated[list, add_messages]


def new_state(
    ip_address: str,
    role: str = "analyst",
    action: str = "network.ingress",
    context: dict[str, Any] | None = None,
) -> ReviewState:
    return ReviewState(
        correlation_id=str(uuid4()),
        submitted_at=datetime.now(timezone.utc).isoformat(),
        ip_address=ip_address,
        role=role,
        action=action,
        context=context or {},
        findings=[],
        verdict="review",
        severity="low",
        trust_score=1.0,
        firewall_command=None,
        ip_valid=False,
        halt_reason=None,
        messages=[],
    )

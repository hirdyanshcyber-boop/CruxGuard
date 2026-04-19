"""APRA CPS 234 / CPS 230 audit logger.

Produces one durable JSON record per review. Record fields map directly to
the CPS 234 control clauses required for board-reportable evidence.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean

from src.config import SETTINGS
from src.state import AgentFinding, ReviewState

_CPS234_CLAUSES = {
    "asset_id": "CPS234.14 — information asset identification",
    "control_test": "CPS234.26 — security control testing",
    "third_party": "CPS234.22 — third-party security assurance",
    "incident_class": "CPS234.35 — incident response (72h notification)",
    "board_reportable": "CPS234.11 — board accountability",
}


def _compute_trust(findings: list[AgentFinding]) -> float:
    scores = [f.get("confidence", 0.0) for f in findings if f.get("agent") != "WorkflowManager"]
    return round(mean(scores), 4) if scores else 0.0


def _is_board_reportable(state: ReviewState) -> bool:
    return state.get("severity") in {"high", "critical"} or state.get("verdict") == "deny"


def audit_logger_node(state: ReviewState) -> ReviewState:
    start = time.perf_counter()
    trust_score = _compute_trust(state.get("findings", []))
    state["trust_score"] = trust_score

    record = {
        "correlation_id": state.get("correlation_id"),
        "submitted_at": state.get("submitted_at"),
        "finalised_at": datetime.now(timezone.utc).isoformat(),
        "ip_address": state.get("ip_address"),
        "role": state.get("role"),
        "action": state.get("action"),
        "verdict": state.get("verdict"),
        "severity": state.get("severity"),
        "trust_score": trust_score,
        "firewall_command": state.get("firewall_command"),
        "halt_reason": state.get("halt_reason"),
        "findings": state.get("findings", []),
        "cps234_mapping": {
            "asset_id": {"value": state.get("ip_address"), "clause": _CPS234_CLAUSES["asset_id"]},
            "control_test": {
                "value": [f["agent"] for f in state.get("findings", [])],
                "clause": _CPS234_CLAUSES["control_test"],
            },
            "third_party": {"value": "AbuseIPDB", "clause": _CPS234_CLAUSES["third_party"]},
            "incident_class": {"value": state.get("severity"), "clause": _CPS234_CLAUSES["incident_class"]},
            "board_reportable": {
                "value": _is_board_reportable(state),
                "clause": _CPS234_CLAUSES["board_reportable"],
            },
        },
    }

    out_dir: Path = SETTINGS.audit_log_path
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{state.get('correlation_id')}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, default=str)

    state["findings"].append(
        {
            "agent": "AuditLogger",
            "decision": "persisted",
            "confidence": 1.0,
            "rationale": f"CPS 234 record written to {path}",
            "evidence": {"path": str(path), "board_reportable": _is_board_reportable(state)},
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "latency_ms": (time.perf_counter() - start) * 1000,
        }
    )
    return state

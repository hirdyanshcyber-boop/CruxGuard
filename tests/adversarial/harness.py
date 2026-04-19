"""Adversarial test harness — runs the graph against the attack corpus
across a range of temperatures and collects per-attempt outcomes.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, asdict
from typing import Iterable

from src.graph import build_graph
from src.state import new_state

from .attacks import ATTACKS, AttackCase


@dataclass
class AttemptResult:
    attack_id: str
    category: str
    temperature: float
    round_index: int
    verdict: str
    severity: str
    trust_score: float
    prompt_injection_detected: bool
    latency_ms: float
    resisted: bool  # True if verdict != "allow"


def _set_temperature(t: float) -> None:
    os.environ["GEMMA_TEMPERATURE"] = str(t)


def _run_single(graph, case: AttackCase, temperature: float, round_index: int) -> AttemptResult:
    state = new_state(
        ip_address=case.ip,
        role=case.role,
        action=case.action,
        context=case.context,
    )
    start = time.perf_counter()
    final = graph.invoke(state)
    elapsed = (time.perf_counter() - start) * 1000.0

    analyser = next(
        (f for f in final["findings"] if f["agent"] == "ThreatAnalyserAgent"),
        None,
    )
    injection_flag = bool(
        (analyser or {}).get("evidence", {}).get("prompt_injection_detected", False)
    )

    verdict = final.get("verdict", "review")
    return AttemptResult(
        attack_id=case.id,
        category=case.category,
        temperature=temperature,
        round_index=round_index,
        verdict=verdict,
        severity=final.get("severity", "low"),
        trust_score=final.get("trust_score", 0.0),
        prompt_injection_detected=injection_flag,
        latency_ms=elapsed,
        resisted=(verdict != "allow"),
    )


def run_sweep(
    temperatures: Iterable[float] = (0.1, 0.3, 0.5, 0.7, 1.0),
    rounds_per_attack: int = 2,
    cases: list[AttackCase] | None = None,
) -> list[dict]:
    """Run the attack corpus at each temperature.

    Returns a list of `AttemptResult` dicts so the caller can feed a
    reporter without importing dataclass internals.
    """
    graph = build_graph()
    cases = cases or ATTACKS
    all_results: list[AttemptResult] = []

    for t in temperatures:
        _set_temperature(t)
        # Rebuild graph so the new temperature is picked up by Gemma client.
        # (Config is module-level; re-reading env is cheap.)
        from src.config import load_settings

        import src.config as _cfg

        _cfg.SETTINGS = load_settings()
        graph = build_graph()

        for case in cases:
            for r in range(rounds_per_attack):
                result = _run_single(graph, case, t, r)
                all_results.append(result)

    return [asdict(r) for r in all_results]

# CruxGuard

**Agentic AI Security and Governance Framework for Australian Financial Services**

CruxGuard is a production-grade, cloud-native extension of a Deakin University thesis demonstrating multi-agent LLM-driven threat validation, policy enforcement, and APRA CPS 234 / CPS 230 audit evidence generation.

The name comes from the Southern Cross (*Crux*) on the Australian flag — navigation for institutions moving through the AI threat landscape.

## The review graph

CruxGuard coordinates five agents as a state graph:

```
          ┌─────────────────┐
          │ WorkflowManager │  (entry)
          └────────┬────────┘
                   │
                   ▼
          ┌─────────────────┐      invalid
          │ IPValidator     │─────────────┐
          └────────┬────────┘             │
                   │ valid                │
                   ▼                      │
          ┌─────────────────┐             │
          │ ThreatAnalyser  │ (Gemma 4)   │
          └────────┬────────┘             │
                   │                      │
                   ▼                      │
          ┌─────────────────┐             │
          │ PolicyEnforcer  │             │
          └────────┬────────┘             │
                   │                      │
                   ▼                      │
          ┌─────────────────┐             │
          │ FirewallUpdater │             │
          └────────┬────────┘             │
                   │                      │
                   ▼                      ▼
          ┌─────────────────────────────────┐
          │ AuditLogger (CPS 234 evidence)  │
          └─────────────────────────────────┘
```

Every edge transition, confidence score, and LLM prompt is persisted to a JSON audit trail suitable for APRA evidence.

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env           # add GOOGLE_API_KEY and ABUSEIPDB_API_KEY
python main.py --ip 8.8.8.8 --role analyst
```

## Layout

| Path | Purpose |
|---|---|
| `src/graph.py` | LangGraph review graph — wires the five agents |
| `src/state.py` | Typed shared state passed between agents |
| `src/agents/` | One file per agent |
| `src/tools/` | AbuseIPDB client, Gemma 4 client, prompt logger |
| `src/compliance/` | CPS 234 audit logger and trust scorer |
| `tests/` | Functional, adversarial, and temperature-sensitivity tests |
| `main.py` | CLI entry point |

## Regulatory mapping

Every decision record contains fields mapped to APRA CPS 234 clauses:
`information_asset`, `control_tested`, `third_party_source`, `incident_class`, `decision_timestamp`, `board_reportable`.

## Adversarial testing

CruxGuard ships with a five-category adversarial harness covering direct
prompt injection, indirect injection, role-play jailbreak, confidence
manipulation, and multi-turn context poisoning.

```bash
python scripts/run_adversarial.py              # default sweep
python scripts/run_adversarial.py --quick      # smoke test
python scripts/run_adversarial.py --temperatures 0.1 0.3 --rounds 3
```

The runner emits:

- `tests/adversarial/out/adversarial_results.csv` — one row per attempt
- `tests/adversarial/out/adversarial_metrics.json` — aggregated metrics
- `RESULTS.md` — human-readable report at the repo root

See [RESULTS.md](./RESULTS.md) for the latest measured resistance rates.

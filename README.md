# CruxGuard

**An AI security guard for Australian banks.**

CruxGuard is a security guard for AI systems used by banks. When someone or something tries to access a bank's network — let's say a suspicious IP address — CruxGuard passes the request through five specialist AI agents, one after another, like a review panel. The first agent checks if the address is even valid. The second uses a large language model called Gemma 4 to reason about whether the request looks like a real threat, including whether someone is trying to trick the AI with prompt injection (the new favourite hacker technique). The third agent checks if the person's role is even allowed to do what they're asking. The fourth agent writes out the firewall rule that should apply. The fifth agent saves the whole decision — every step, every reason, every confidence score — as a tamper-proof JSON audit record mapped to Australia's APRA CPS 234 banking compliance rules. This matters because 97% of companies have zero AI governance controls, APRA auditors are actively inspecting banks in 2026, and a single breach in financial services costs six million dollars on average. CruxGuard makes the AI auditable, testable, and defendable — and I've run over 100 adversarial attack rounds against it to prove the agents don't fall for prompt injection tricks.

The name comes from the Southern Cross (*Crux*) on the Australian flag — a compass for institutions navigating the AI threat landscape.

## Why this exists

- **97% of organisations** have no controls over their internal AI use (IBM 2025)
- **$6.08 million** is the average cost of a financial services data breach (IBM 2025)
- **APRA CPS 230** became active in July 2025 and auditors are inspecting now
- **AI-enabled fraud** is projected to hit **$40 billion by 2027**
- Banks are adopting agentic AI faster than they can govern it — CruxGuard closes that gap

## How it works — the five-agent review graph

Every request walks through this pipeline. If something breaks, it stops early and is still logged.

```
          ┌─────────────────┐
          │ WorkflowManager │  accepts the request
          └────────┬────────┘
                   │
                   ▼
          ┌─────────────────┐      invalid address
          │ IPValidator     │─────────────┐
          └────────┬────────┘             │
                   │ valid                │
                   ▼                      │
          ┌─────────────────┐             │
          │ ThreatAnalyser  │  ← Gemma 4 LLM reasoning
          └────────┬────────┘     (spots prompt injection too)
                   │                      │
                   ▼                      │
          ┌─────────────────┐             │
          │ PolicyEnforcer  │  ← role-based + attribute-based access
          └────────┬────────┘             │
                   │                      │
                   ▼                      │
          ┌─────────────────┐             │
          │ FirewallUpdater │  ← renders the allow/deny rule
          └────────┬────────┘             │
                   │                      │
                   ▼                      ▼
          ┌─────────────────────────────────┐
          │ AuditLogger (APRA CPS 234 ready) │
          └─────────────────────────────────┘
```

**Every step — every reason, every confidence score, every prompt — is saved as a JSON file.** That file is what you hand an APRA auditor.

## What each agent does

| Agent | Plain-English job |
|---|---|
| **WorkflowManager** | Accepts the request and starts the review |
| **IPValidator** | Checks the IP address is real, then queries AbuseIPDB for its reputation |
| **ThreatAnalyser** | Uses the Gemma 4 language model to reason about whether the request is dangerous — also detects prompt injection attempts |
| **PolicyEnforcer** | Checks if the person's role is allowed to do what they're asking (Zero Trust, least privilege) |
| **FirewallUpdater** | Writes the firewall rule that should apply (allow / deny / quarantine) |
| **AuditLogger** | Saves the full decision as a compliance record mapped to APRA CPS 234 |

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env           # add GOOGLE_API_KEY and ABUSEIPDB_API_KEY
python main.py --ip 8.8.8.8 --role analyst
```

Try these to see different verdicts:

```bash
python main.py --ip not.an.ip --role analyst                          # → deny (bad format)
python main.py --ip 1.1.1.1 --role guest --action firewall.update     # → deny (not allowed)
python main.py --ip 185.220.101.1 --role engineer                     # → flagged (Tor exit)
```

Each run drops a JSON audit file into `./audit/` — open one to see the full evidence record.

## Project layout

| Path | Purpose |
|---|---|
| `src/graph.py` | The review graph — wires the five agents together |
| `src/state.py` | The shared state that flows between agents |
| `src/agents/` | One file per agent |
| `src/tools/` | Gemma 4 client, AbuseIPDB client, prompt logger |
| `src/compliance/` | CPS 234 audit logger |
| `tests/` | Functional tests |
| `tests/adversarial/` | Prompt injection + jailbreak test corpus |
| `scripts/run_adversarial.py` | Runs the attack sweep and writes RESULTS.md |
| `main.py` | Command-line entry point |

## Regulatory mapping

Every audit record carries fields mapped to APRA CPS 234 clauses:

- **Information asset** — which IP was being reviewed
- **Control tested** — which agents ran the check
- **Third-party source** — AbuseIPDB used for threat intel
- **Incident class** — severity level (low / medium / high / critical)
- **Decision timestamp** — exact time, in ISO 8601
- **Board reportable** — flagged true when severity ≥ high or the decision was a deny

The same structure can be extended to EU AI Act (August 2026) and post-quantum crypto controls.

## Adversarial testing

CruxGuard ships with a five-category attack corpus — direct prompt injection, indirect (payload-in-data) injection, role-play jailbreak attempts, confidence manipulation, and multi-turn context poisoning.

```bash
python scripts/run_adversarial.py              # full sweep (5 temperatures, ~120 attacks)
python scripts/run_adversarial.py --quick      # smoke test (12 attacks)
python scripts/run_adversarial.py --temperatures 0.1 0.3 --rounds 3
```

The runner writes:

- `tests/adversarial/out/adversarial_results.csv` — one row per attempt
- `tests/adversarial/out/adversarial_metrics.json` — aggregate numbers
- `RESULTS.md` — human-readable report at the repo root

See [RESULTS.md](./RESULTS.md) for the latest measured resistance rates.

## Tech stack

Everything runs on free tiers.

| Component | Tool |
|---|---|
| Language model | Gemma 4 via Google AI Studio |
| Threat intel | AbuseIPDB |
| Cloud (planned) | AWS Lambda, API Gateway, S3, DynamoDB, CloudWatch |
| Language | Python 3.11+ |
| Graph engine | LangGraph |
| CI | GitHub Actions |

## Built by

**Hirdyansh Dudi** — Master of Cyber Security (Distinction), Deakin University, Geelong, Australia. CHFI certified. Interested in AI security engineering, agentic system governance, and fraud risk roles in Australian financial services.

"""Run the CruxGuard adversarial test suite and write RESULTS.md.

Usage:
    python scripts/run_adversarial.py
    python scripts/run_adversarial.py --temperatures 0.1 0.3 0.7 --rounds 3
    python scripts/run_adversarial.py --quick   # one temperature, one round
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as a script from the repo root.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.adversarial.harness import run_sweep  # noqa: E402
from tests.adversarial.report import write_outputs  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CruxGuard adversarial sweep")
    parser.add_argument(
        "--temperatures",
        nargs="+",
        type=float,
        default=[0.1, 0.3, 0.5, 0.7, 1.0],
        help="Temperatures to sweep (default: 0.1 0.3 0.5 0.7 1.0)",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=2,
        help="Rounds per attack per temperature (default: 2)",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run a minimal smoke sweep (one temperature, one round).",
    )
    args = parser.parse_args(argv)

    if args.quick:
        temperatures = [0.3]
        rounds = 1
    else:
        temperatures = args.temperatures
        rounds = args.rounds

    total = len(temperatures) * 12 * rounds  # 12 attacks in the default corpus
    print(f"Running {total} graph invocations "
          f"({len(temperatures)} temps × 12 attacks × {rounds} rounds) ...")

    results = run_sweep(temperatures=temperatures, rounds_per_attack=rounds)

    out_dir = ROOT / "tests" / "adversarial" / "out"
    metrics = write_outputs(results, out_dir)

    # Also stage the headline RESULTS.md at repo root for easy discovery.
    (ROOT / "RESULTS.md").write_text(
        (out_dir / "RESULTS.md").read_text(encoding="utf-8"), encoding="utf-8"
    )

    print("\nOverall resistance: "
          f"{metrics['overall']['overall_resistance_pct']}% "
          f"({metrics['overall']['total_rounds']} rounds)")
    print(f"Wrote:\n  {out_dir / 'adversarial_results.csv'}\n"
          f"  {out_dir / 'adversarial_metrics.json'}\n"
          f"  {out_dir / 'RESULTS.md'}\n"
          f"  {ROOT / 'RESULTS.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

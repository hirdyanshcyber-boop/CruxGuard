"""CruxGuard CLI entry point.

Example:
    python main.py --ip 8.8.8.8 --role analyst --action network.ingress
"""

from __future__ import annotations

import argparse
import json
import sys

from src.graph import GRAPH
from src.state import new_state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a CruxGuard review.")
    parser.add_argument("--ip", required=True, help="IP address under review")
    parser.add_argument("--role", default="analyst", help="Requesting principal role")
    parser.add_argument("--action", default="network.ingress", help="Action requested")
    parser.add_argument("--context", default="{}", help="Extra JSON context")
    args = parser.parse_args(argv)

    try:
        context = json.loads(args.context)
    except json.JSONDecodeError as exc:
        print(f"Invalid --context JSON: {exc}", file=sys.stderr)
        return 2

    state = new_state(ip_address=args.ip, role=args.role, action=args.action, context=context)
    final = GRAPH.invoke(state)

    print(
        json.dumps(
            {
                "correlation_id": final["correlation_id"],
                "verdict": final["verdict"],
                "severity": final.get("severity"),
                "trust_score": final.get("trust_score"),
                "firewall_command": final.get("firewall_command"),
                "findings": final["findings"],
            },
            indent=2,
            default=str,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

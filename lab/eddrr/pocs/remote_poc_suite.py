from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from remote_cases import CASES


def main() -> int:
    print("EDDRR remote-technique false-negative PoC suite")
    print("=" * 72)

    reproduced = 0

    for finding_id, title, factory in CASES:
        engine, events = factory()
        alerts = []
        for event in events:
            alerts.extend(engine.detect(event))

        observed = [alert.finding_id for alert in alerts]
        missed = finding_id not in observed

        status = "PASS" if missed else "FAIL"
        print(f"[{status}] {finding_id} {title}")
        print(f"       observed alerts: {observed}")

        if missed:
            reproduced += 1

    print()
    print(f"Reproduced {reproduced}/{len(CASES)} intended false negatives.")

    if reproduced != len(CASES):
        return 1

    print("All remote-technique PoCs are synthetic and non-networked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

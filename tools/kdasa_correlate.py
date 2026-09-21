#!/usr/bin/env python3
"""Correlate two KDASA JSONL telemetry sources offline.

The correlator is deliberately evidence-only. It does not connect to live
processes, modify telemetry, or interact with drivers.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


def load(path: Path, source: str) -> list[dict]:
    result = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: invalid JSON on line {n}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}: line {n} is not an object")
            value["_source"] = source
            result.append(value)
    return result


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def signature(event: dict) -> tuple:
    return (
        str(event.get("Type", "")),
        int(event.get("Pid", -1)),
        int(event.get("Tid", -1)),
        str(event.get("ProcessName", "")),
    )


def correlate(left: list[dict], right: list[dict], tolerance_ms: float) -> dict:
    unmatched_right = set(range(len(right)))
    matches = []
    deltas = []

    for left_index, event in enumerate(left):
        best_index = None
        best_delta = None
        for idx in unmatched_right:
            candidate = right[idx]
            if signature(event) != signature(candidate):
                continue
            delta = abs((parse_ts(event["Timestamp"]) - parse_ts(candidate["Timestamp"])).total_seconds() * 1000)
            if delta <= tolerance_ms and (best_delta is None or delta < best_delta):
                best_index = idx
                best_delta = delta

        if best_index is not None:
            unmatched_right.remove(best_index)
            matches.append((left_index, best_index, best_delta))
            deltas.append(best_delta)

    matched_left = {x[0] for x in matches}

    type_left = Counter(str(e.get("Type", "Unknown")) for e in left)
    type_right = Counter(str(e.get("Type", "Unknown")) for e in right)

    return {
        "leftCount": len(left),
        "rightCount": len(right),
        "matchedCount": len(matches),
        "leftUnmatchedCount": len(left) - len(matched_left),
        "rightUnmatchedCount": len(unmatched_right),
        "matchRateLeft": round(len(matches) / len(left), 4) if left else 1.0,
        "matchRateRight": round(len(matches) / len(right), 4) if right else 1.0,
        "medianDeltaMs": round(sorted(deltas)[len(deltas) // 2], 3) if deltas else None,
        "maxDeltaMs": round(max(deltas), 3) if deltas else None,
        "leftEventTypes": dict(sorted(type_left.items())),
        "rightEventTypes": dict(sorted(type_right.items())),
        "unmatchedRightEvents": [right[i] for i in sorted(unmatched_right)[:100]],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--tolerance-ms", type=float, default=50.0)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    result = correlate(
        load(args.left, "left"),
        load(args.right, "right"),
        args.tolerance_ms,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote correlation report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

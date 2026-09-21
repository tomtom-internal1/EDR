#!/usr/bin/env python3
"""Analyze KDASA ETW JSONL telemetry.

This tool is intentionally offline: it reads captured JSONL and produces
deterministic statistics without interacting with processes or drivers.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def load(path: Path) -> list[dict]:
    events: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_no}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"Line {line_no} is not a JSON object")
            events.append(value)
    return events


def analyze(events: list[dict]) -> dict:
    type_counts = Counter(str(e.get("Type", "Unknown")) for e in events)
    process_names = Counter(
        str(e.get("ProcessName", "<unknown>"))
        for e in events
        if e.get("Type") == "ProcessStart"
    )

    pids: dict[int, dict[str, object]] = {}
    for event in events:
        if event.get("Type") == "ProcessStart":
            pid = int(event.get("Pid", -1))
            details = event.get("Details") or {}
            pids[pid] = {
                "pid": pid,
                "parentPid": details.get("parentPid"),
                "imageFileName": details.get("imageFileName"),
                "commandLine": details.get("commandLine"),
                "timestamp": event.get("Timestamp"),
            }

    image_loads_by_pid: dict[int, int] = defaultdict(int)
    for event in events:
        if event.get("Type") == "ImageLoad":
            image_loads_by_pid[int(event.get("Pid", -1))] += 1

    return {
        "eventCount": len(events),
        "eventTypes": dict(sorted(type_counts.items())),
        "processStartsByName": dict(process_names.most_common()),
        "uniqueProcessStarts": len(pids),
        "processTreeRoots": sum(
            1 for item in pids.values()
            if not isinstance(item.get("parentPid"), int) or item["parentPid"] <= 0
        ),
        "topImageLoadPids": [
            {"pid": pid, "count": count}
            for pid, count in sorted(image_loads_by_pid.items(), key=lambda pair: pair[1], reverse=True)[:20]
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    summary = analyze(load(args.input))
    rendered = json.dumps(summary, indent=2, ensure_ascii=False)

    if args.output:
        args.output.write_text(rendered + "
", encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

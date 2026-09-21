#!/usr/bin/env python3
"""Merge KDASA evidence artifacts into one assessment bundle.

All inputs are pre-collected artifacts. This tool performs no live system
interaction and does not infer exploitability.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def read(path: Path | None) -> dict | None:
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--pe", type=Path)
    parser.add_argument("--advisory", type=Path)
    parser.add_argument("--blocklist", type=Path)
    parser.add_argument("--score", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    inventory = read(args.inventory)
    pe = read(args.pe)
    advisory = read(args.advisory)
    blocklist = read(args.blocklist)
    score = read(args.score)

    driver = {
        "path": (inventory or {}).get("resolvedPath") or (pe or {}).get("path"),
        "sha256": (pe or {}).get("sha256") or (blocklist or {}).get("sha256"),
        "company": (inventory or {}).get("company"),
        "fileVersion": (inventory or {}).get("fileVersion"),
        "signatureStatus": (inventory or {}).get("signatureStatus"),
    }

    result = {
        "generatedUtc": datetime.now(timezone.utc).isoformat(),
        "driver": driver,
        "evidence": {
            "inventory": inventory,
            "pe": pe,
            "advisoryMatches": advisory,
            "blocklist": blocklist,
            "reviewScore": score,
        },
        "interpretation": {
            "exactBlocklistMatch": bool((blocklist or {}).get("exactHashMatch")),
            "advisoryMatchCount": (advisory or {}).get("matchCount", 0),
            "reviewPriority": (score or {}).get("priority"),
        },
        "note": "This bundle preserves evidence from separate collectors. It is not an exploitability or compromise verdict.",
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote assessment bundle to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

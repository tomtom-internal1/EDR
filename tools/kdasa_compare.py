#!/usr/bin/env python3
"""Compare two KDASA assessment bundles offline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def read(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def compare(before: dict, after: dict) -> dict:
    before_driver = before.get("driver", {})
    after_driver = after.get("driver", {})
    before_ev = before.get("evidence", {})
    after_ev = after.get("evidence", {})

    before_pe = before_ev.get("pe") or {}
    after_pe = after_ev.get("pe") or {}
    before_score = before_ev.get("reviewScore") or {}
    after_score = after_ev.get("reviewScore") or {}
    before_block = before_ev.get("blocklist") or {}
    after_block = after_ev.get("blocklist") or {}

    changed_fields = []
    for field in ("path", "sha256", "company", "fileVersion", "signatureStatus"):
        if before_driver.get(field) != after_driver.get(field):
            changed_fields.append(field)

    mitigation_changes = {}
    for key in sorted(set((before_pe.get("mitigations") or {}).keys()) | set((after_pe.get("mitigations") or {}).keys())):
        old = (before_pe.get("mitigations") or {}).get(key)
        new = (after_pe.get("mitigations") or {}).get(key)
        if old != new:
            mitigation_changes[key] = {"before": old, "after": new}

    return {
        "driverFieldChanges": changed_fields,
        "sha256Changed": before_driver.get("sha256") != after_driver.get("sha256"),
        "signatureStatusChanged": before_driver.get("signatureStatus") != after_driver.get("signatureStatus"),
        "mitigationChanges": mitigation_changes,
        "writableExecutableSectionsBefore": before_pe.get("writableExecutableSections", []),
        "writableExecutableSectionsAfter": after_pe.get("writableExecutableSections", []),
        "blocklistMatchBefore": bool(before_block.get("exactHashMatch")),
        "blocklistMatchAfter": bool(after_block.get("exactHashMatch")),
        "reviewScoreBefore": before_score.get("score"),
        "reviewScoreAfter": after_score.get("score"),
        "reviewPriorityBefore": before_score.get("priority"),
        "reviewPriorityAfter": after_score.get("priority"),
        "note": "Comparison highlights observed changes; it does not infer exploitability or root cause.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    result = compare(read(args.before), read(args.after))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "
", encoding="utf-8")
    print(f"Wrote comparison report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

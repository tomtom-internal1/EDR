#!/usr/bin/env python3
"""Assign a review-priority score from KDASA evidence.

This is a triage aid, not a vulnerability verdict. Every point must be
traceable to an observed property or an explicitly supplied advisory match.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def score(pe: dict, signature_status: str | None = None, known_advisory: bool = False) -> dict:
    points = 0
    evidence: list[str] = []

    mitigations = pe.get("mitigations", {})

    if signature_status and signature_status.lower() not in {"valid", "validsignatures"}:
        points += 25
        evidence.append(f"signature-status={signature_status}")

    if known_advisory:
        points += 40
        evidence.append("explicit-advisory-match")

    if not mitigations.get("dynamicBase_ASLR", False):
        points += 10
        evidence.append("missing-dynamic-base")

    if not mitigations.get("nxCompat_DEP", False):
        points += 10
        evidence.append("missing-nx-compat")

    wx = pe.get("writableExecutableSections", [])
    if wx:
        points += min(20, 10 + 2 * len(wx))
        evidence.append(f"writable-executable-sections={len(wx)}")

    if not pe.get("hasSecurityDirectory", False):
        points += 10
        evidence.append("no-security-directory")

    points = min(points, 100)

    if points < 20:
        priority = "routine"
    elif points < 45:
        priority = "review"
    elif points < 70:
        priority = "elevated-review"
    else:
        priority = "urgent-review"

    return {
        "score": points,
        "priority": priority,
        "evidence": evidence,
        "note": "Triage signal only; investigate the underlying evidence before making security conclusions.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe_json", type=Path)
    parser.add_argument("--signature-status")
    parser.add_argument("--known-advisory", action="store_true")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    pe = json.loads(args.pe_json.read_text(encoding="utf-8"))
    result = score(pe, args.signature_status, args.known_advisory)
    rendered = json.dumps(result, indent=2)

    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

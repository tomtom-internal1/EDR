#!/usr/bin/env python3
"""Static review linter for Windows driver source files.

This is a heuristic code-review aid. It reports source patterns that deserve
manual review and never compiles, loads, or executes the driver.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


RULES = [
    ("high", "ioctl-method-neither", re.compile(r"METHOD_NEITHER\b"), "METHOD_NEITHER requires especially careful user-buffer validation."),
    ("high", "device-control-dispatch", re.compile(r"IRP_MJ_DEVICE_CONTROL"), "Driver exposes a device-control dispatch surface; review IOCTL validation and access control."),
    ("high", "map-io-space", re.compile(r"\bMmMapIoSpace(?:Ex)?\s*\("), "Physical-memory mapping API deserves focused security review."),
    ("medium", "user-probe", re.compile(r"\bProbeFor(?:Read|Write)\s*\("), "Explicit user-buffer probing is security-sensitive; review exception handling and lengths."),
    ("medium", "raw-memcpy", re.compile(r"\bmemcpy\s*\("), "Raw memory copy requires verified destination/source bounds."),
    ("medium", "unsafe-string", re.compile(r"\b(?:strcpy|strcat|sprintf|vsprintf)\s*\("), "Unbounded string routine should be reviewed for memory-safety risk."),
    ("medium", "named-device", re.compile(r"\b(?:IoCreateDevice|WdfDeviceCreateSymbolicLink)\s*\("), "Named device/symbolic-link surface should be reviewed for intended access control."),
    ("low", "debug-print", re.compile(r"\bDbgPrint(?:Ex)?\s*\("), "Debug output may expose sensitive information; review release builds."),
]


def lint(path: Path) -> list[dict]:
    findings: list[dict] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    for line_no, line in enumerate(lines, 1):
        if line.lstrip().startswith("//"):
            continue
        for severity, rule_id, pattern, message in RULES:
            if pattern.search(line):
                findings.append({
                    "file": str(path),
                    "line": line_no,
                    "severity": severity,
                    "rule": rule_id,
                    "message": message,
                    "source": line.strip(),
                })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    files = [args.source] if args.source.is_file() else sorted(
        p for p in args.source.rglob("*")
        if p.suffix.lower() in {".c", ".cc", ".cpp", ".h", ".hpp"}
    )

    findings = []
    for path in files:
        findings.extend(lint(path))

    summary = {
        "filesScanned": len(files),
        "findingCount": len(findings),
        "countsBySeverity": {
            level: sum(1 for f in findings if f["severity"] == level)
            for level in ("high", "medium", "low")
        },
        "findings": findings,
        "note": "Heuristic source review only. Findings require manual validation and are not vulnerability verdicts.",
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote driver lint report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

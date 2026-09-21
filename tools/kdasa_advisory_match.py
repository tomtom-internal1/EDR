#!/usr/bin/env python3
"""Match a driver record against a local advisory catalog.

The matcher performs exact, evidence-traceable comparisons only. It never
downloads advisories, loads a driver, or interacts with a device interface.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def norm(value: object) -> str:
    return str(value or "").strip().casefold()


def matches(driver: dict, advisory: dict) -> tuple[bool, str, str]:
    driver_hash = norm(driver.get("sha256"))
    hashes = {norm(x) for x in advisory.get("sha256", [])}
    if driver_hash and driver_hash in hashes:
        return True, "exact-hash", "Exact SHA-256 match"

    filename = Path(str(driver.get("path", ""))).name.casefold()
    versions = {norm(x) for x in advisory.get("versions", [])}
    driver_version = norm(driver.get("fileVersion") or driver.get("productVersion"))
    filenames = {norm(x) for x in advisory.get("fileNames", [])}
    if filename and filename in filenames and driver_version and driver_version in versions:
        return True, "filename-version", "Driver filename and exact version match"

    vendor_match = norm(driver.get("company")) == norm(advisory.get("vendor"))
    product_match = norm(driver.get("product")) == norm(advisory.get("product"))
    if vendor_match and product_match and driver_version in versions and driver_version:
        return True, "vendor-product-version", "Vendor, product, and exact version match"

    return False, "none", "No exact catalog match"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("driver_json", type=Path)
    parser.add_argument("catalog_json", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    driver = json.loads(args.driver_json.read_text(encoding="utf-8"))
    catalog = json.loads(args.catalog_json.read_text(encoding="utf-8"))
    findings = []

    for advisory in catalog.get("advisories", []):
        ok, method, reason = matches(driver, advisory)
        if ok:
            findings.append({
                "id": advisory.get("id"),
                "source": advisory.get("source"),
                "sourceUrl": advisory.get("sourceUrl"),
                "matchMethod": method,
                "reason": reason,
            })

    result = {
        "driver": driver.get("path"),
        "sha256": driver.get("sha256"),
        "matches": findings,
        "matchCount": len(findings),
        "confidence": "exact" if any(x["matchMethod"] == "exact-hash" for x in findings) else ("metadata-exact" if findings else "none"),
        "note": "A catalog match is evidence for review, not an independent exploitability determination.",
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote advisory matching report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

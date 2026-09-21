#!/usr/bin/env python3
"""Extract and compare SHA-256 evidence from a local driver-blocklist XML."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def extract_hashes(path: Path) -> set[str]:
    root = ET.parse(path).getroot()
    hashes: set[str] = set()
    for element in root.iter():
        for value in element.attrib.values():
            hashes.update(x.lower() for x in SHA256_RE.findall(value))
        if element.text:
            hashes.update(x.lower() for x in SHA256_RE.findall(element.text))
    return hashes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("driver", type=Path)
    parser.add_argument("blocklist_xml", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    digest = hashlib.sha256(args.driver.read_bytes()).hexdigest().lower()
    blocked_hashes = extract_hashes(args.blocklist_xml)
    result = {
        "driver": str(args.driver),
        "sha256": digest,
        "blocklistFile": str(args.blocklist_xml),
        "sha256HashCount": len(blocked_hashes),
        "exactHashMatch": digest in blocked_hashes,
        "note": "No match means only that this hash was not found in the supplied blocklist snapshot; it is not proof of safety.",
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote blocklist assessment to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Convert a C synthetic PoC JSON object into a RemoteEvent object."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from remote_models import RemoteEvent


def convert(payload: dict) -> RemoteEvent:
    excluded = {"event_type", "poc_id", "technique", "timestamp", "synthetic"}
    metadata = dict(payload.get("metadata") or {})
    metadata["poc_id"] = payload.get("poc_id")
    metadata["synthetic"] = payload.get("synthetic", True)

    return RemoteEvent(
        technique=payload["technique"],
        timestamp=float(payload.get("timestamp", 0.0)),
        source_host=payload["source_host"],
        target_host=payload["target_host"],
        command_line=payload.get("command_line", ""),
        protocol=payload.get("protocol", ""),
        destination_port=int(payload.get("destination_port", 0)),
        session_id=payload.get("session_id", ""),
        metadata=metadata,
    )


def main() -> int:
    if len(sys.argv) != 1:
        print("Read one JSON object from stdin.", file=sys.stderr)
        return 2

    payload = json.load(sys.stdin)
    event = convert(payload)
    print(json.dumps({
        "technique": event.technique,
        "timestamp": event.timestamp,
        "source_host": event.source_host,
        "target_host": event.target_host,
        "command_line": event.command_line,
        "protocol": event.protocol,
        "destination_port": event.destination_port,
        "session_id": event.session_id,
        "metadata": event.metadata,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

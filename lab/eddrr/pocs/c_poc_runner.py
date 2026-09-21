#!/usr/bin/env python3
"""Execute one locally-built synthetic C PoC and submit its JSON to EDDRR.

The child process is one of the repository's own synthetic generators. It
does not open sockets or contact remote hosts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remote_engine import VulnerableRemoteEDR


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    args = parser.parse_args()

    completed = subprocess.run(
        [str(args.executable)],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(completed.stdout)
    engine = VulnerableRemoteEDR()

    # The training PoC suite expects a RemoteEvent-shaped object.
    from remote_models import RemoteEvent
    event = RemoteEvent(
        technique=payload["technique"],
        timestamp=float(payload.get("timestamp", 0.0)),
        source_host=payload["source_host"],
        target_host=payload["target_host"],
        command_line=payload.get("command_line", ""),
        protocol=payload.get("protocol", ""),
        destination_port=int(payload.get("destination_port", 0)),
        session_id=payload.get("session_id", ""),
        metadata=payload.get("metadata") or {},
    )

    alerts = engine.detect(event)

    print(json.dumps({
        "poc_id": payload.get("poc_id"),
        "technique": payload["technique"],
        "observed_alerts": [
            {
                "finding_id": alert.finding_id,
                "title": alert.title,
                "severity": alert.severity,
            }
            for alert in alerts
        ],
        "false_negative": len(alerts) == 0,
        "synthetic": payload.get("synthetic", True),
    }, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

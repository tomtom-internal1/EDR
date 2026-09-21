from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine import VulnerableEDR
from models import Event
from storage import Store


def main() -> int:
    parser = argparse.ArgumentParser(description="EDDRR training EDR")
    parser.add_argument("events", type=Path)
    parser.add_argument("--db", type=Path, default=Path("out/eddrr.db"))
    args = parser.parse_args()

    args.db.parent.mkdir(parents=True, exist_ok=True)
    store = Store(args.db)
    engine = VulnerableEDR()
    alerts = 0

    with args.events.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            if not line.strip():
                continue
            raw = json.loads(line)
            event = Event(**raw)
            event_id = store.add_event(event)
            for alert in engine.detect(event):
                store.add_alert(alert, event_id)
                alerts += 1

    store.close()
    print(f"processed={args.events} alerts={alerts} db={args.db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

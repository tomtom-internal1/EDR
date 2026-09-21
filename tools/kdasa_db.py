#!/usr/bin/env python3
"""Persist KDASA research evidence in a local SQLite database."""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_utc TEXT NOT NULL,
    label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(run_id),
    source TEXT NOT NULL,
    event_type TEXT,
    pid INTEGER,
    tid INTEGER,
    timestamp_utc TEXT,
    process_name TEXT,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence(run_id);
CREATE INDEX IF NOT EXISTS idx_evidence_pid ON evidence(pid);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(event_type);
"""

def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)

def create_run(conn: sqlite3.Connection, label: str) -> int:
    cur = conn.execute("INSERT INTO runs(created_utc, label) VALUES(datetime('now'), ?)", (label,))
    conn.commit()
    return int(cur.lastrowid)

def import_jsonl(conn: sqlite3.Connection, run_id: int, path: Path, source: str) -> int:
    inserted = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: invalid JSON on line {line_no}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"{path}: line {line_no} is not an object")
            conn.execute(
                "INSERT INTO evidence(run_id, source, event_type, pid, tid, timestamp_utc, process_name, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, source, event.get("Type"), event.get("Pid"), event.get("Tid"),
                 event.get("Timestamp"), event.get("ProcessName"),
                 json.dumps(event, ensure_ascii=False, sort_keys=True)),
            )
            inserted += 1
    conn.commit()
    return inserted

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    parser.add_argument("--label", default="unnamed-run")
    parser.add_argument("--jsonl", type=Path)
    parser.add_argument("--source", default="unknown")
    args = parser.parse_args()
    args.database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(args.database) as conn:
        init_db(conn)
        run_id = create_run(conn, args.label)
        count = import_jsonl(conn, run_id, args.jsonl, args.source) if args.jsonl else 0
    print(f"run_id={run_id} imported={count}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

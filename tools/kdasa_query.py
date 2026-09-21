#!/usr/bin/env python3
"""Query KDASA SQLite evidence without touching the live system."""
from __future__ import annotations
import argparse
import json
import sqlite3

def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("database")
    p.add_argument("--run-id", type=int)
    p.add_argument("--type")
    p.add_argument("--pid", type=int)
    p.add_argument("--source")
    p.add_argument("--limit", type=int, default=100)
    a=p.parse_args()
    where=[]; params=[]
    if a.run_id is not None: where.append("run_id=?"); params.append(a.run_id)
    if a.type: where.append("event_type=?"); params.append(a.type)
    if a.pid is not None: where.append("pid=?"); params.append(a.pid)
    if a.source: where.append("source=?"); params.append(a.source)
    sql="SELECT evidence_id, run_id, source, event_type, pid, tid, timestamp_utc, process_name, payload_json FROM evidence"
    if where: sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY timestamp_utc, evidence_id LIMIT ?"; params.append(max(1,a.limit))
    with sqlite3.connect(a.database) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute(sql, params).fetchall()
    for row in rows:
        item=dict(row)
        try: item["payload"]=json.loads(item.pop("payload_json"))
        except json.JSONDecodeError: pass
        print(json.dumps(item, ensure_ascii=False))
    return 0

if __name__=="__main__":
    raise SystemExit(main())

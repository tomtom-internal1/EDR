from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from models import Alert, Event


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                timestamp REAL,
                pid INTEGER,
                tid INTEGER,
                image TEXT,
                parent_pid INTEGER,
                command_line TEXT,
                source TEXT,
                signature_status TEXT,
                metadata TEXT
            )"""
        )
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT,
                severity TEXT,
                title TEXT,
                event_id INTEGER
            )"""
        )
        self.conn.commit()

    def add_event(self, event: Event) -> int:
        cur = self.conn.execute(
            """INSERT INTO events
            (event_type,timestamp,pid,tid,image,parent_pid,command_line,source,signature_status,metadata)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                event.event_type,
                event.timestamp,
                event.pid,
                event.tid,
                event.image,
                event.parent_pid,
                event.command_line,
                event.source,
                event.signature_status,
                json.dumps(event.metadata, sort_keys=True),
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def add_alert(self, alert: Alert, event_id: int) -> None:
        self.conn.execute(
            "INSERT INTO alerts(rule_id,severity,title,event_id) VALUES(?,?,?,?)",
            (alert.rule_id, alert.severity, alert.title, event_id),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

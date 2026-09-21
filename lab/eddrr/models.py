from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Event:
    event_type: str
    timestamp: float
    pid: int
    tid: int = 0
    image: str = ""
    parent_pid: int = 0
    command_line: str = ""
    source: str = "simulator"
    signature_status: str | None = "Valid"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Alert:
    rule_id: str
    severity: str
    title: str
    event: Event
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CollectorStats:
    received: int = 0
    dropped: int = 0
    deduplicated: int = 0

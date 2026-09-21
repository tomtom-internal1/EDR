from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class RemoteEvent:
    technique: str
    timestamp: float
    source_host: str
    target_host: str
    account: str = ""
    process_image: str = ""
    command_line: str = ""
    protocol: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    destination_port: int = 0
    session_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RemoteAlert:
    finding_id: str
    title: str
    severity: str
    event: RemoteEvent

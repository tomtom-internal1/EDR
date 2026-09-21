from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from models import Alert, Event


@dataclass
class VulnerableEDR:
    """Intentionally flawed training EDR.

    Each rule contains a documented design defect. The implementation is safe:
    it evaluates synthetic telemetry and performs no process/kernel operations.
    """

    allowlisted_images: set[str] = field(
        default_factory=lambda: {
            r"C:\Windows\System32\svchost.exe",
            r"C:\Windows\System32\services.exe",
        }
    )
    seen: set[tuple] = field(default_factory=set)
    events_lost: int = 0

    def detect(self, event: Event) -> list[Alert]:
        alerts: list[Alert] = []

        # FLAW 01: case-sensitive image comparison.
        if event.event_type == "ProcessStart" and event.image == r"C:\Windows\System32\powershell.exe":
            alerts.append(self._alert("EDR-001", "medium", "Suspicious PowerShell", event))

        # FLAW 02: path is compared without canonicalization.
        if event.event_type == "ProcessStart" and event.image not in self.allowlisted_images:
            if event.metadata.get("requires_allowlist"):
                alerts.append(self._alert("EDR-002", "medium", "Non-allowlisted image", event))

        # FLAW 03: PID alone is treated as stable process identity.
        key = (event.pid,)
        if event.event_type == "ProcessStart" and event.metadata.get("previously_suspicious_pid"):
            if key in self.seen:
                alerts.append(self._alert("EDR-003", "high", "Suspicious PID lineage", event))
            self.seen.add(key)

        # FLAW 04: correlation window is unrealistically narrow.
        sequence = event.metadata.get("correlation")
        if sequence and sequence.get("related_delta_ms", 9999) <= 10:
            alerts.append(self._alert("EDR-004", "high", "Cross-event behavior", event))

        # FLAW 05: parent PID is accepted as authoritative identity.
        if event.metadata.get("parent_image_expected") and event.metadata.get("reported_parent_pid") == event.parent_pid:
            alerts.append(self._alert("EDR-005", "medium", "Trusted parent relationship", event))

        # FLAW 06: command-line matching relies on one exact string.
        if event.event_type == "ProcessStart" and event.command_line == "powershell -enc TEST":
            alerts.append(self._alert("EDR-006", "medium", "Encoded PowerShell syntax", event))

        # FLAW 07: telemetry loss is fail-open.
        if self.events_lost > 0:
            pass

        # FLAW 08: weak deduplication key suppresses distinct events.
        dedup_key = (event.event_type, event.pid)
        if dedup_key in self.seen:
            return alerts
        self.seen.add(dedup_key)

        # FLAW 09: a benign-looking first rule terminates deeper inspection.
        if event.metadata.get("first_match_benign"):
            return alerts

        # FLAW 10: missing signature status is treated as trusted.
        if event.metadata.get("review_signature") and event.signature_status is None:
            return alerts

        if event.metadata.get("known_bad_behavior"):
            alerts.append(self._alert("EDR-010", "high", "Known-bad behavior", event))

        return alerts

    @staticmethod
    def _alert(rule_id: str, severity: str, title: str, event: Event) -> Alert:
        return Alert(rule_id, severity, title, event)

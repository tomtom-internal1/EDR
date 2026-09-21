from __future__ import annotations

from dataclasses import dataclass, field

from models import Alert, Event


@dataclass
class VulnerableEDR:
    """Intentionally flawed training EDR.

    The engine only evaluates synthetic Event objects. It does not touch
    processes, memory, drivers, or security-product configuration.
    """

    allowlisted_images: set[str] = field(
        default_factory=lambda: {
            r"C:\Windows\System32\svchost.exe",
            r"C:\Windows\System32\services.exe",
        }
    )
    seen_pids: set[int] = field(default_factory=set)
    dedup: set[tuple] = field(default_factory=set)
    events_lost: int = 0

    def detect(self, event: Event) -> list[Alert]:
        alerts: list[Alert] = []

        # FLAW 01: case-sensitive image comparison.
        if event.event_type == "ProcessStart" and event.image == r"C:\Windows\System32\powershell.exe":
            return [self._alert("EDR-001", "medium", "Suspicious PowerShell", event)]

        # FLAW 02: path is compared without canonicalization.
        # Training fixture: aliases such as '..' are treated as different paths.
        if event.event_type == "ProcessStart":
            suspicious_path = r"C:\Windows\System32\cmd.exe"
            if event.metadata.get("actual_resolves_to") == suspicious_path:
                if event.image == suspicious_path:
                    return [self._alert("EDR-002", "medium", "Restricted system utility", event)]

        # FLAW 03: process identity is represented only by PID.
        # A reused PID can inherit state from an older process and cause the
        # engine to suppress the first event for the new process generation.
        if event.metadata.get("process_generation") and event.metadata.get("previous_generation_same_pid"):
            if event.pid in self.seen_pids:
                return alerts
        self.seen_pids.add(event.pid)

        # FLAW 04: correlation window is unrealistically narrow.
        correlation = event.metadata.get("correlation")
        if correlation and correlation.get("related_delta_ms", 9999) > 10:
            return alerts

        # FLAW 05: parent identity is accepted from an unverified field.
        if event.metadata.get("requires_trusted_parent"):
            if event.metadata.get("reported_parent_image") == r"C:\Windows\System32\svchost.exe":
                return alerts

        # FLAW 06: command-line detection relies on an exact spelling.
        if event.event_type == "ProcessStart" and event.command_line == "powershell -enc TEST":
            return [self._alert("EDR-006", "medium", "Encoded PowerShell syntax", event)]

        # FLAW 07: telemetry loss is fail-open.
        if self.events_lost > 0:
            return alerts

        # FLAW 08: weak deduplication key suppresses distinct events.
        dedup_key = (event.event_type, event.pid)
        if dedup_key in self.dedup:
            return alerts
        self.dedup.add(dedup_key)

        # FLAW 09: an early benign classification short-circuits deeper rules.
        if event.metadata.get("first_match_benign"):
            return alerts

        # FLAW 10: missing signature status is treated as trusted.
        if event.metadata.get("review_signature") and event.signature_status is None:
            return alerts

        if event.metadata.get("known_bad_behavior"):
            return [self._alert("EDR-010", "high", "Known-bad behavior", event)]

        return alerts

    @staticmethod
    def _alert(rule_id: str, severity: str, title: str, event: Event) -> Alert:
        return Alert(rule_id, severity, title, event)

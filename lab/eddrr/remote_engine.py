from __future__ import annotations

from dataclasses import dataclass, field

from remote_models import RemoteAlert, RemoteEvent


@dataclass
class VulnerableRemoteEDR:
    """Intentionally flawed remote-activity detector.

    It consumes only synthetic RemoteEvent objects. No network connections,
    remote commands, or payload execution are performed.
    """

    def detect(self, event: RemoteEvent) -> list[RemoteAlert]:
        # FLAW R01: WMI detection trusts a local-host flag and ignores origin.
        if event.technique == "WMI_REMOTE_EXEC":
            if event.metadata.get("local_process_created") is True:
                return [self._alert("R01", "WMI activity", "medium", event)]
            return []

        # FLAW R02: WinRM detection uses one exact port instead of protocol/session evidence.
        if event.technique == "WINRM_REMOTE_EXEC":
            if event.destination_port == 5985 and event.protocol == "WinRM":
                return [self._alert("R02", "WinRM remote execution", "medium", event)]
            return []

        # FLAW R03: SMB detection only considers the initial connection.
        if event.technique == "SMB_ADMIN_SHARE":
            if event.metadata.get("share_connection_only"):
                return []
            if event.metadata.get("file_write_after_share"):
                return [self._alert("R03", "SMB administrative share activity", "high", event)]
            return []

        # FLAW R04: RDP detector ignores authentication/session context.
        if event.technique == "RDP_REMOTE_SESSION":
            if event.metadata.get("interactive_logon") and event.metadata.get("approved_user"):
                return []
            return []

        # FLAW R05: service detector sees creation but not remote target/start relationship.
        if event.technique == "REMOTE_SERVICE_EXEC":
            if event.metadata.get("service_created") and not event.metadata.get("service_started"):
                return []
            if event.metadata.get("service_started") and event.source_host == event.target_host:
                return [self._alert("R05", "Service execution", "high", event)]
            return []

        # FLAW R06: scheduled-task detector only inspects tasks created locally.
        if event.technique == "REMOTE_SCHEDULED_TASK":
            if event.source_host == event.target_host:
                return [self._alert("R06", "Scheduled task execution", "medium", event)]
            return []

        # FLAW R07: PowerShell detection depends on one literal token.
        if event.technique == "POWERSHELL_REMOTE":
            if "-EncodedCommand" in event.command_line:
                return [self._alert("R07", "PowerShell encoded-command syntax", "medium", event)]
            return []

        # FLAW R08: cmd detection is case-sensitive.
        if event.technique == "CMD_REMOTE":
            if "cmd.exe /c" in event.command_line:
                return [self._alert("R08", "Windows command shell", "medium", event)]
            return []

        # FLAW R09: ingress-transfer detection depends only on file extension.
        if event.technique == "REMOTE_TRANSFER":
            if event.metadata.get("filename", "").lower().endswith(".exe"):
                return [self._alert("R09", "Remote file transfer", "medium", event)]
            return []

        # FLAW R10: HTTP C2-like detection trusts one User-Agent string.
        if event.technique == "WEB_C2_SIM":
            if event.metadata.get("user_agent") == "EDDRR-Test-Agent":
                return [self._alert("R10", "Web application traffic", "medium", event)]
            return []

        return []

    @staticmethod
    def _alert(finding_id: str, title: str, severity: str, event: RemoteEvent) -> RemoteAlert:
        return RemoteAlert(finding_id, title, severity, event)

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from remote_engine import VulnerableRemoteEDR
from remote_models import RemoteEvent


def r1():
    return VulnerableRemoteEDR(), [RemoteEvent(
        technique="WMI_REMOTE_EXEC",
        timestamp=1.0,
        source_host="ADMIN-01",
        target_host="SERVER-01",
        protocol="WMI",
        metadata={"local_process_created": False, "remote_process_created": True},
    )]


def r2():
    return VulnerableRemoteEDR(), [RemoteEvent(
        technique="WINRM_REMOTE_EXEC",
        timestamp=2.0,
        source_host="ADMIN-01",
        target_host="SERVER-01",
        protocol="WinRM",
        destination_port=5986,
        metadata={"remote_command_result": "simulated"},
    )]


def r3():
    return VulnerableRemoteEDR(), [RemoteEvent(
        technique="SMB_ADMIN_SHARE",
        timestamp=3.0,
        source_host="ADMIN-01",
        target_host="SERVER-01",
        protocol="SMB",
        destination_port=445,
        metadata={"share_connection_only": True, "file_write_after_share": False},
    )]


def r4():
    return VulnerableRemoteEDR(), [RemoteEvent(
        technique="RDP_REMOTE_SESSION",
        timestamp=4.0,
        source_host="LAPTOP-01",
        target_host="SERVER-01",
        protocol="RDP",
        session_id="SIM-04",
        metadata={"interactive_logon": True, "approved_user": True, "after_hours": True},
    )]


def r5():
    return VulnerableRemoteEDR(), [RemoteEvent(
        technique="REMOTE_SERVICE_EXEC",
        timestamp=5.0,
        source_host="ADMIN-01",
        target_host="SERVER-01",
        metadata={"service_created": True, "service_started": True, "remote_target": True},
    )]


def r6():
    return VulnerableRemoteEDR(), [RemoteEvent(
        technique="REMOTE_SCHEDULED_TASK",
        timestamp=6.0,
        source_host="ADMIN-01",
        target_host="SERVER-01",
        metadata={"remote_task_created": True},
    )]


def r7():
    return VulnerableRemoteEDR(), [RemoteEvent(
        technique="POWERSHELL_REMOTE",
        timestamp=7.0,
        source_host="ADMIN-01",
        target_host="SERVER-01",
        command_line="powershell -e TEST",
        metadata={"encoded_command_semantics": True},
    )]


def r8():
    return VulnerableRemoteEDR(), [RemoteEvent(
        technique="CMD_REMOTE",
        timestamp=8.0,
        source_host="ADMIN-01",
        target_host="SERVER-01",
        command_line="CMD.EXE /C whoami",
    )]


def r9():
    return VulnerableRemoteEDR(), [RemoteEvent(
        technique="REMOTE_TRANSFER",
        timestamp=9.0,
        source_host="ADMIN-01",
        target_host="SERVER-01",
        metadata={"filename": "diagnostic.bin", "content_type": "application/x-binary"},
    )]


def r10():
    return VulnerableRemoteEDR(), [RemoteEvent(
        technique="WEB_C2_SIM",
        timestamp=10.0,
        source_host="WORKSTATION-01",
        target_host="WEB-01",
        protocol="HTTP",
        destination_port=443,
        destination_ip="172.22.23.53",
        metadata={"user_agent": "Mozilla/5.0", "periodic": True, "small_response": True},
    )]


CASES = [
    ("R01", "WMI remote execution", r1),
    ("R02", "WinRM remote execution", r2),
    ("R03", "SMB administrative share", r3),
    ("R04", "RDP remote session", r4),
    ("R05", "Remote service execution", r5),
    ("R06", "Remote scheduled task", r6),
    ("R07", "PowerShell remote command", r7),
    ("R08", "Windows command shell", r8),
    ("R09", "Remote file transfer", r9),
    ("R10", "Web traffic / C2 simulation", r10),
]

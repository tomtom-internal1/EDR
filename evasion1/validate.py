#!/usr/bin/env python3
"""Validate Evasion1 JSONL outputs and enforce the lab's safety invariants."""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
ART = ROOT / "artifacts"

EXPECTED = {
    "p01_syscall_visibility": ("P01_SYSCALL_VISIBILITY", {"ApiResolution","UserApiOperation","NtdllExportOperation","DetectionOracle"}),
    "p02_parent_context": ("P02_PARENT_CONTEXT", {"ProcessCreateIntent","LineageCrossCheck","DetectionOracle"}),
    "p03_apc_execution": ("P03_APC_EXECUTION", {"ThreadStart","ApcQueue","ApcCallback","CorrelationResult"}),
    "p04_timer_callback": ("P04_TIMER_CALLBACK", {"TimerRegistration","TimerCallback","DetectionOracle"}),
    "p05_memory_transition": ("P05_MEMORY_TRANSITION", {"SectionCreate","SectionWrite","ProtectionTransition","DetectionOracle"}),
    "p06_dll_context": ("P06_DLL_CONTEXT", {"DllSearchPolicy","ImageLoad","ExportResolution","DetectionOracle"}),
    "p07_etw_degradation": ("P07_ETW_DEGRADATION", {"ProviderRegistered","EtwWrite","DetectionOracle"}),
    "p08_ipv6_telemetry": ("P08_IPV6_TELEMETRY", {"Listen","Connection","DetectionOracle"}),
    "p09_local_ipc": ("P09_LOCAL_IPC", {"NamedPipeCreate","ChildProcessCreate","PipeTransfer","RegistryIpc","DetectionOracle"}),
    "p10_kernel_sensor_integrity": ("P10_KERNEL_SENSOR_INTEGRITY", {"GroundTruthBaseline","GroundTruthThreadChange","SensorMirrorObservation","DetectionOracle"}),
}


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    raise SystemExit(1)


def main() -> int:
    if not ART.exists():
        fail(f"missing artifact directory: {ART}")

    for stem, (expected_id, expected_events) in EXPECTED.items():
        path = ART / f"{stem}.jsonl"
        if not path.exists():
            fail(f"missing {path}")

        events = []
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                fail(f"{path.name}:{number}: invalid JSON: {exc}")
            events.append(event)

        if not events:
            fail(f"{path.name}: empty output")

        actual_id = events[0].get("poc_id")
        if actual_id != expected_id:
            fail(f"{path.name}: expected poc_id {expected_id}, got {actual_id}")

        actual_events = {e.get("event_type") for e in events}
        missing = expected_events - actual_events
        if missing:
            fail(f"{path.name}: missing event types: {sorted(missing)}")

        serialized = path.read_text(encoding="utf-8")
        if '"operational_bypass":true' in serialized:
            fail(f"{path.name}: operational bypass marker present")
        if '"payload_execution":true' in serialized:
            fail(f"{path.name}: payload execution marker present")

        for e in events:
            if e.get("details", {}).get("kernel_write_performed") is True:
                fail(f"{path.name}: kernel write invariant violated")

    print(f"[PASS] validated {len(EXPECTED)} Evasion1 scenarios")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

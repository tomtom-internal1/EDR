from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts"

EXPECTED = {
    "p01_early_bird_apc": {"A01_EARLY_BIRD_APC", "ApcQueuedBeforeResume", "ApcCallback", "CorrelationResult"},
    "p02_threadpool_timer": {"A02_THREADPOOL_TIMER", "ThreadpoolTimerRegister", "ThreadpoolCallback", "DetectionOracle"},
    "p03_enumwindows_callback": {"A03_ENUMWINDOWS_CALLBACK", "EnumerationStart", "EnumerationResult", "DetectionOracle"},
    "p04_hw_breakpoint_veh": {"A04_HW_BREAKPOINT_VEH", "HardwareBreakpointArmed", "HardwareBreakpointHit", "DetectionOracle"},
    "p05_native_thread_introspection": {"A05_NATIVE_THREAD_INTROSPECTION", "NativeThreadQuery", "DetectionOracle"},
    "p06_etw_private_session": {"A06_ETW_PRIVATE_SESSION", "SessionStarted", "SessionQuery", "SessionStopped", "DetectionOracle"},
    "p07_amsi_multipath": {"A07_AMSI_MULTIPATH", "AmsiScan", "CrossPathCorrelation", "DetectionOracle"},
    "p08_sec_image_mapping": {"A08_SEC_IMAGE_MAPPING", "ImageSectionMapped", "ImageInspection", "DetectionOracle"},
    "p09_socket_groundtruth": {"A09_SOCKET_GROUNDTRUTH", "SocketGroundTruth", "DetectionOracle"},
    "p10_wait_callback": {"A10_WAIT_CALLBACK", "WaitRegistration", "WaitCallback", "CallbackCorrelation", "DetectionOracle"},
}

def main() -> int:
    for stem, expected in EXPECTED.items():
        path = ART / f"{stem}.jsonl"
        if not path.exists():
            raise SystemExit(f"[FAIL] missing {path}")
        events = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
        types = {e.get("event_type") for e in events}
        missing = expected - types
        if missing:
            raise SystemExit(f"[FAIL] {stem}: missing {sorted(missing)}")

        raw = path.read_text(encoding="utf-8").lower()
        if '"remote_process":true' in raw:
            raise SystemExit(f"[FAIL] {stem}: remote-process invariant violated")
        if '"code_modified":true' in raw:
            raise SystemExit(f"[FAIL] {stem}: code modification invariant violated")
        if '"memory_patch":true' in raw:
            raise SystemExit(f"[FAIL] {stem}: memory-patch invariant violated")

    print(f"[PASS] {len(EXPECTED)} advanced scenarios validated")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

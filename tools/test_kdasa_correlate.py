import importlib.util
from datetime import datetime, timezone
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "kdasa_correlate", Path(__file__).with_name("kdasa_correlate.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def event(ts: str, tid: int = 2) -> dict:
    return {
        "Type": "ProcessStart",
        "Timestamp": ts,
        "Pid": 100,
        "Tid": tid,
        "ProcessName": "sample",
    }


def test_correlation_with_tolerance() -> None:
    left = [event("2026-09-21T05:30:00.000Z")]
    right = [event("2026-09-21T05:30:00.020Z")]

    result = MODULE.correlate(left, right, 50)

    assert result["matchedCount"] == 1
    assert result["leftUnmatchedCount"] == 0
    assert result["rightUnmatchedCount"] == 0
    assert result["medianDeltaMs"] == 20.0


def test_unmatched_event() -> None:
    left = [event("2026-09-21T05:30:00.000Z")]
    right = [event("2026-09-21T05:30:01.000Z")]

    result = MODULE.correlate(left, right, 50)

    assert result["matchedCount"] == 0
    assert result["leftUnmatchedCount"] == 1
    assert result["rightUnmatchedCount"] == 1

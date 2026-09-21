import json
import importlib.util
from pathlib import Path
import tempfile


SPEC = importlib.util.spec_from_file_location(
    "kdasa_report", Path(__file__).with_name("kdasa_report.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_report_generation() -> None:
    telemetry = {"eventCount": 4, "uniqueProcessStarts": 1}
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        telemetry_path = root / "telemetry.json"
        report_path = root / "report.html"
        telemetry_path.write_text(json.dumps(telemetry), encoding="utf-8")

        import sys
        old_argv = sys.argv
        try:
            sys.argv = [
                "kdasa_report.py",
                "--telemetry-summary",
                str(telemetry_path),
                "-o",
                str(report_path),
            ]
            assert MODULE.main() == 0
        finally:
            sys.argv = old_argv

        text = report_path.read_text(encoding="utf-8")
        assert "KDASA Security Research Report" in text
        assert "Telemetry events" in text
        assert "4" in text

from pathlib import Path
import subprocess
import sys


def test_legacy_sample_parser_still_runs() -> None:
    parser = Path(__file__).with_name("parse_dbgprint.py")
    sample = Path(__file__).with_name("sample_dbgprint.log")
    if not parser.exists() or not sample.exists():
        return

    completed = subprocess.run(
        [sys.executable, str(parser), str(sample)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "PROC_CREATE" in completed.stdout

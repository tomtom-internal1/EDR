import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory

spec = importlib.util.spec_from_file_location(
    "kdasa_assess", Path(__file__).with_name("kdasa_assess.py")
)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def test_assessment_bundle() -> None:
    with TemporaryDirectory() as td:
        root = Path(td)
        pe = root / "pe.json"
        blocklist = root / "block.json"
        score = root / "score.json"
        out = root / "assessment.json"

        pe.write_text(json.dumps({"path": "example.sys", "sha256": "a" * 64}), encoding="utf-8")
        blocklist.write_text(json.dumps({"sha256": "a" * 64, "exactHashMatch": True}), encoding="utf-8")
        score.write_text(json.dumps({"priority": "review"}), encoding="utf-8")

        import sys
        old_argv = sys.argv
        try:
            sys.argv = [
                "kdasa_assess.py",
                "--pe", str(pe),
                "--blocklist", str(blocklist),
                "--score", str(score),
                "-o", str(out),
            ]
            assert module.main() == 0
        finally:
            sys.argv = old_argv

        result = json.loads(out.read_text(encoding="utf-8"))
        assert result["driver"]["sha256"] == "a" * 64
        assert result["interpretation"]["exactBlocklistMatch"] is True

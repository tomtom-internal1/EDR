import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "kdasa_advisory_match", Path(__file__).with_name("kdasa_advisory_match.py")
)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def test_exact_hash_has_highest_confidence() -> None:
    driver = {"path": "example.sys", "sha256": "ABC123", "fileVersion": "1.2.3"}
    advisory = {
        "id": "X",
        "sha256": ["abc123"],
        "fileNames": ["example.sys"],
        "versions": ["1.2.3"],
    }
    ok, method, _ = module.matches(driver, advisory)
    assert ok
    assert method == "exact-hash"


def test_filename_version_match() -> None:
    driver = {
        "path": r"C:\Windows\System32\drivers\example.sys",
        "fileVersion": "1.2.3",
    }
    advisory = {"fileNames": ["example.sys"], "versions": ["1.2.3"]}
    ok, method, _ = module.matches(driver, advisory)
    assert ok
    assert method == "filename-version"

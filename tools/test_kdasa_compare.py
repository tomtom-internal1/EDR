import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "kdasa_compare", Path(__file__).with_name("kdasa_compare.py")
)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def test_detects_driver_and_mitigation_changes() -> None:
    before = {
        "driver": {"sha256": "old", "signatureStatus": "Valid"},
        "evidence": {
            "pe": {"mitigations": {"dynamicBase_ASLR": False}, "writableExecutableSections": [".text"]},
            "blocklist": {"exactHashMatch": False},
            "reviewScore": {"score": 20, "priority": "review"},
        },
    }
    after = {
        "driver": {"sha256": "new", "signatureStatus": "Valid"},
        "evidence": {
            "pe": {"mitigations": {"dynamicBase_ASLR": True}, "writableExecutableSections": []},
            "blocklist": {"exactHashMatch": True},
            "reviewScore": {"score": 50, "priority": "elevated-review"},
        },
    }

    result = module.compare(before, after)
    assert result["sha256Changed"] is True
    assert result["mitigationChanges"]["dynamicBase_ASLR"] == {"before": False, "after": True}
    assert result["blocklistMatchAfter"] is True
    assert result["reviewScoreAfter"] == 50

import importlib.util
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "kdasa_score", Path(__file__).with_name("kdasa_score.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_score_is_traceable() -> None:
    pe = {
        "mitigations": {
            "dynamicBase_ASLR": False,
            "nxCompat_DEP": True,
        },
        "writableExecutableSections": [".text"],
        "hasSecurityDirectory": False,
    }

    result = MODULE.score(pe)
    assert result["score"] == 40
    assert "missing-dynamic-base" in result["evidence"]
    assert "writable-executable-sections=1" in result["evidence"]
    assert "no-security-directory" in result["evidence"]

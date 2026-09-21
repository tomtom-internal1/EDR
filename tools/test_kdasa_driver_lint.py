import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory

spec = importlib.util.spec_from_file_location(
    "kdasa_driver_lint", Path(__file__).with_name("kdasa_driver_lint.py")
)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def test_flags_review_sensitive_patterns() -> None:
    with TemporaryDirectory() as td:
        path = Path(td) / "sample.c"
        path.write_text(
            'case IRP_MJ_DEVICE_CONTROL:\n'
            '  /* review */\n'
            '  if (method == METHOD_NEITHER) {}\n'
            '  memcpy(dst, src, len);\n',
            encoding="utf-8",
        )
        findings = module.lint(path)

    rules = {finding["rule"] for finding in findings}
    assert "device-control-dispatch" in rules
    assert "ioctl-method-neither" in rules
    assert "raw-memcpy" in rules

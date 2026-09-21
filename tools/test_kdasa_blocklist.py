import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory

spec = importlib.util.spec_from_file_location(
    "kdasa_blocklist", Path(__file__).with_name("kdasa_blocklist.py")
)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def test_hash_extraction() -> None:
    with TemporaryDirectory() as td:
        root = Path(td)
        xml = root / "block.xml"
        digest = "a" * 64
        xml.write_text(f'<Root><File Hash="{digest}" /></Root>', encoding="utf-8")
        assert digest in module.extract_hashes(xml)

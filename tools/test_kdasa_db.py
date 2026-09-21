import importlib.util
import json
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory

spec = importlib.util.spec_from_file_location("kdasa_db", Path(__file__).with_name("kdasa_db.py"))
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)

def test_sqlite_import() -> None:
    with TemporaryDirectory() as td:
        root = Path(td)
        db = root / "evidence.db"
        capture = root / "capture.jsonl"
        capture.write_text(json.dumps({"Type":"ProcessStart","Timestamp":"2026-09-21T05:30:00Z","Pid":10,"Tid":20,"ProcessName":"sample"}) + "\n", encoding="utf-8")
        with sqlite3.connect(db) as conn:
            module.init_db(conn)
            run_id = module.create_run(conn, "test")
            assert module.import_jsonl(conn, run_id, capture, "etw") == 1
            row = conn.execute("SELECT source, event_type, pid FROM evidence").fetchone()
            assert row == ("etw", "ProcessStart", 10)

# KDASA Analysis CLI

The Python analyzer consumes ETW collector JSONL captures and produces deterministic JSON summaries.

Example:

    python tools/kdasa_analyze.py tools/sample_kdasa.jsonl

Or write a report:

    python tools/kdasa_analyze.py tools/sample_kdasa.jsonl -o out/summary.json

The analyzer does not collect telemetry itself and does not interact with live processes.

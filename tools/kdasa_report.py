#!/usr/bin/env python3
"""Generate a self-contained HTML report from KDASA evidence JSON files."""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any


def load_json(path: Path | None) -> Any:
    if path is None:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def preformatted(value: Any) -> str:
    return html.escape(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--telemetry-summary", type=Path)
    parser.add_argument("--pe-json", type=Path)
    parser.add_argument("--inventory-json", type=Path)
    parser.add_argument("--score-json", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    telemetry = load_json(args.telemetry_summary)
    pe = load_json(args.pe_json)
    inventory = load_json(args.inventory_json)
    score = load_json(args.score_json)

    title = "KDASA Security Research Report"

    cards = []
    if telemetry:
        cards.append(("Telemetry events", telemetry.get("eventCount", 0)))
        cards.append(("Unique process starts", telemetry.get("uniqueProcessStarts", 0)))
    if pe:
        cards.append(("Architecture", pe.get("machine", "unknown")))
        cards.append(("PE sections", pe.get("sectionCount", 0)))
    if score:
        cards.append(("Review score", score.get("score", 0)))
        cards.append(("Priority", score.get("priority", "unknown")))

    card_html = "".join(
        f'<div class="card"><div class="label">{html.escape(str(k))}</div>'
        f'<div class="value">{html.escape(str(v))}</div></div>'
        for k, v in cards
    )

    sections = []
    for heading, value in [
        ("Telemetry summary", telemetry),
        ("PE analysis", pe),
        ("Driver inventory", inventory),
        ("Review scoring", score),
    ]:
        if value is not None:
            sections.append(
                f"<section><h2>{html.escape(heading)}</h2><pre>{preformatted(value)}</pre></section>"
            )

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;line-height:1.45}}
.cards{{display:flex;gap:14px;flex-wrap:wrap;margin:20px 0 30px}}
.card{{border:1px solid #ccc;border-radius:10px;padding:14px 18px;min-width:150px}}
.label{{font-size:.85rem;color:#666}} .value{{font-size:1.35rem;font-weight:700;margin-top:5px}}
section{{margin:28px 0}} pre{{background:#f6f6f6;border:1px solid #ddd;border-radius:8px;padding:16px;overflow:auto}}
.note{{padding:12px;border-left:4px solid #777;background:#fafafa}}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p class="note">This is an evidence and triage report. A score does not establish exploitability or compromise.</p>
<div class="cards">{card_html}</div>
{"".join(sections)}
</body>
</html>
"""

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(document, encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

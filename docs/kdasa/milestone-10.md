# Milestone 10 — Unified Driver Assessment

KDASA now combines inventory, PE, advisory, blocklist, and scoring artifacts into one JSON assessment bundle.

## Evidence-first design

The bundle keeps the original inputs under evidence.* while exposing a small interpretation block for downstream reporting.

The interpretation deliberately uses narrow facts:

- exact blocklist hash match
- advisory match count
- review-priority label

No field is intended to state that a driver is exploitable or malicious without separate supporting analysis.

## Example

```powershell
python tools/kdasa_assess.py \
  --inventory out\driver.json \
  --pe out\driver-pe.json \
  --advisory out\advisory.json \
  --blocklist out\blocklist.json \
  --score out\score.json \
  -o out\assessment.json
```

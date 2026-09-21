# Milestone 06 — Telemetry Correlation

KDASA now includes an offline correlator for comparing two JSONL event streams.

## Matching

Events are considered candidates when they share:

- event type
- PID
- TID
- process name

A configurable timestamp tolerance then determines whether the records are treated as the same observation.

## Metrics

The correlator produces:

- total events per source
- matched events
- unmatched events
- left/right match rates
- median timestamp delta
- maximum timestamp delta
- event-type distributions

## Interpretation

This is a measurement tool, not an evasion detector. A non-match can arise from buffering, provider configuration, timestamp conversion, duplicate events, parser differences, or genuinely different source semantics.

## Example

\`\`\`powershell
python tools/kdasa_correlate.py left.jsonl right.jsonl --tolerance-ms 50 -o out\\correlation.json
\`\`\`

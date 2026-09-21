# KDASA Data Model

## runs

A run represents one controlled experiment.

Fields: run_id, created_utc, label.

## evidence

A row represents one observed event.

Fields: source, event_type, pid, tid, timestamp_utc, process_name, payload_json.

## Design rule

Normalized columns support fast correlation and indexing. payload_json is retained so source-specific fields are not discarded.

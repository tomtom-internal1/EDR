# Milestone 07 — SQLite Evidence Store

KDASA can persist telemetry captures in a local SQLite database.

## Schema

- runs records an experimental run and its label.
- evidence stores normalized event identifiers plus the original JSON payload.

## Why SQLite?

It enables repeatable cross-run queries, indexed PID/event-type lookups, preservation of original evidence, and a stable backend for a future GUI.

The database is local and requires no service account, network listener, or remote telemetry transport.

Example invocation:

    python tools/kdasa_db.py out\\evidence.db --label baseline-01 --jsonl out\\events.jsonl --source etw

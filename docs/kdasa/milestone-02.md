# Milestone 02 — Dual-Sensor Telemetry

KDASA now combines two observation paths:

1. Kernel notification callbacks from the research driver.
2. Kernel ETW telemetry from the user-mode collector.

The goal is to measure overlap and differences rather than treating either source as a complete EDR sensor.

## Data model

Normalize both sources to UTC timestamp, event type, PID, TID, process name, source, and event-specific fields.

## Next analysis

Calculate source coverage, matched-event percentage, median timestamp delta, unmatched lifecycle events, and duplicates.

Telemetry absence is not proof of evasion; first investigate provider configuration, event semantics, timing, buffer loss, and parser behavior.

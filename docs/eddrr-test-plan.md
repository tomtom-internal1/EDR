# EDDRR Ten-Finding Test Plan

## Objective

Validate whether the intentionally vulnerable detection engine misses behaviors when endpoint telemetry varies in representation, timing, provenance, or completeness.

## Finding classes

### EDDRR-001 — Case normalization
Input: same executable identity with different path casing.
Expected property: executable identity comparison is case-insensitive after normalization.
PoC: POC 01.

### EDDRR-002 — Path canonicalization
Input: equivalent Windows path containing a parent-directory alias.
Expected property: policy compares canonical identities.
PoC: POC 02.

### EDDRR-003 — Process identity
Input: two process generations reuse the same PID.
Expected property: PID alone is never a unique process identity.
PoC: POC 03.

### EDDRR-004 — Temporal correlation
Input: related events arrive with a 120 ms gap.
Expected property: correlation tolerates bounded scheduling and collection jitter.
PoC: POC 04.

### EDDRR-005 — Parent provenance
Input: reported parent metadata conflicts with independently supplied parent evidence.
Expected property: parent trust is based on corroborated provenance.
PoC: POC 05.

### EDDRR-006 — Command-line normalization
Input: equivalent command syntax with whitespace/case variation.
Expected property: detection is based on normalized semantics rather than one literal spelling.
PoC: POC 06.

### EDDRR-007 — Telemetry-loss handling
Input: collector reports dropped events.
Expected property: degraded visibility becomes an explicit state and does not suppress high-confidence detections.
PoC: POC 07.

### EDDRR-008 — Event identity/deduplication
Input: two distinct events share type and PID.
Expected property: deduplication uses a sufficiently strong identity.
PoC: POC 08.

### EDDRR-009 — Rule evaluation
Input: low-confidence benign classification followed by stronger evidence.
Expected property: weak classification does not terminate higher-confidence evaluation.
PoC: POC 09.

### EDDRR-010 — Unknown trust state
Input: signature state is unknown.
Expected property: unknown is treated as unknown and is not silently trusted.
PoC: POC 10.

## Engineer requirement

For each case, the engineer must reproduce the failure, identify the exact source-level assumption, implement a fix, add a regression test, and document false-positive implications.

## Scope boundary

All PoCs are synthetic Event objects. No process injection, memory manipulation, kernel tampering, or EDR/Defender modification is performed.

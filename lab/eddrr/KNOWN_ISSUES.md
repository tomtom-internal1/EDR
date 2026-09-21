# Intentional EDDRR Defects

Each item is an engineering exercise using synthetic telemetry.

EDR-001 — Case-sensitive image matching: equivalent executable casing is missed.
EDR-002 — Missing path canonicalization: equivalent path aliases are treated inconsistently.
EDR-003 — PID-only identity state: PID reuse can cross process generations.
EDR-004 — Narrow correlation window: delayed or reordered events break a behavior sequence.
EDR-005 — Unverified parent identity: a reported trusted parent can override stronger evidence.
EDR-006 — Exact command-line string: harmless syntax variation defeats lexical matching.
EDR-007 — Fail-open event loss: missing telemetry suppresses defensive action.
EDR-008 — Weak deduplication key: distinct events collide and are discarded.
EDR-009 — Early benign short-circuit: low-confidence classification prevents later rules.
EDR-010 — Missing-signature fail-open: unknown trust state is treated as trusted.

Required evidence for each finding:

- PoC output
- affected source location
- root cause
- expected security property
- remediation
- regression test
- false-positive analysis

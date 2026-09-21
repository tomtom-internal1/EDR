# Milestone 04 — Evidence-Based Review Scoring

KDASA can now convert observed PE properties into a review-priority score.

## Inputs

- Authenticode status from the Windows inventory stage
- Explicit advisory match
- ASLR compatibility
- NX/DEP compatibility
- Writable/executable section observations
- Presence of the PE security directory

## Philosophy

The score is intentionally a triage mechanism rather than a claim that a driver is exploitable. A reviewer should be able to trace every point back to observable evidence.

## Suggested workflow

1. Inventory a running driver.
2. Hash and parse the driver offline.
3. Validate its signature.
4. Check a curated advisory dataset.
5. Run the scoring tool.
6. Manually review the evidence before remediation or escalation.

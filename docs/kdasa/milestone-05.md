# Milestone 05 — Static Research Reporting

KDASA can now generate a self-contained HTML report from normalized evidence.

## Inputs

- ETW telemetry summary
- Offline PE analysis
- Driver inventory
- Review-priority score

## Reporting properties

- No external JavaScript or CDN dependencies
- Raw evidence retained in the report
- HTML escaping applied to collected strings
- Explicit statement that triage scores are not exploitability verdicts

## Reproducibility

A lab run can now follow this pipeline:

    collect -> normalize -> analyze -> inspect -> score -> report

This makes the research artifact easier to archive, compare across Windows builds, and review later.

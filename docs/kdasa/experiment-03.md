# Experiment 03 — Benign Process-Event Stress

## Objective

Measure whether process lifecycle telemetry remains complete under controlled, high-volume benign process creation.

## Workload

Use tools/Invoke-KdasaWorkload.ps1. It launches cmd.exe with an immediate exit and does not execute external payloads.

## Procedure

1. Start the ETW collector.
2. Start the kernel callback sensor.
3. Run the workload with 100, then 500, then 1000 iterations.
4. Stop collection.
5. Count ProcessStart and ProcessStop events.
6. Compare counts between the two telemetry paths.
7. Record any collection-loss indicators available from the session.

## Interpretation

A mismatch is an observation requiring investigation. Possible explanations include event buffering, session configuration, parser behavior, timestamp grouping, or callback lifecycle semantics.

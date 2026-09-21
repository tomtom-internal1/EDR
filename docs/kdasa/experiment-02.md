# Experiment 02 — Kernel Callback vs ETW Coverage

## Objective

Compare two legitimate Windows telemetry paths under a benign workload.

## Procedure

1. Start the KDASA driver sensor.
2. Start the user-mode ETW collector.
3. Record five minutes of baseline workstation activity.
4. Run ordinary applications and a benign process-launch workload.
5. Stop the collector.
6. Normalize timestamps to UTC.
7. Correlate events by PID/TID and nearest timestamp.
8. Produce coverage statistics.

## Metrics

- Process events observed by each source
- Thread events observed by each source
- Image-load events observed by each source
- Matched-event percentage
- Median timestamp delta
- Maximum timestamp delta
- Unmatched events
- Duplicate events

## Expected outcome

Produce an evidence-based coverage matrix instead of a binary 'EDR sees / does not see' conclusion.

# Telemetry Correlation Model

KDASA now has two observation paths:

1. Kernel notification callbacks from the research driver.
2. Kernel ETW consumed by the user-mode collector.

The experiment is to compare their observations rather than treating either source as a complete EDR sensor.

## Correlation key

Use PID, TID, timestamp, event type, and image name.

```text
ProcessStart
    |
    +--> first ThreadStart
    |
    +--> ImageLoad events
    |
    +--> additional ThreadStart events
    |
    +--> ProcessStop
```

## Research questions

- Do both sensors observe the same lifecycle boundaries?
- How large is the timestamp delta between sources?
- Are event orders stable across repeated runs?
- Which fields exist in one source but not the other?
- Are events lost under sustained benign process churn?

Telemetry absence is not proof of evasion; first rule out provider configuration, collection loss, callback semantics, timing, and parser limitations.

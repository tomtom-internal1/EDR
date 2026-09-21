# EDR Research Lab

A defensive security research repository focused on Windows endpoint telemetry, kernel visibility, and detection engineering.

## Research modules

- **KDASA — Kernel Driver Attack Surface Analyzer**
  - Read-only kernel telemetry
  - Process/thread/image notifications
  - User-mode ETW collection
  - Driver inventory
  - Offline event analysis
  - PE/signature/vulnerability-analysis roadmap

The repository deliberately avoids security-product tampering, arbitrary kernel memory access, code injection, and operational EDR bypass tooling.

## KDASA milestones

### Milestone 1 — Kernel telemetry
Implemented documented process, thread, and image-load callbacks in the research driver.

### Milestone 2 — Dual-sensor telemetry
Implemented a .NET ETW collector for process, thread, and image-load events and added an analysis CLI for JSONL captures.

### Milestone 3 — Driver inventory
Added a PowerShell inventory script for running system drivers, versions, publishers, and Authenticode status.

### Next
Offline PE security-property extraction, vulnerability intelligence correlation, and a configurable evidence-based risk model.

## Documentation

- [KDASA overview](docs/kdasa/README.md)
- [Architecture](docs/kdasa/architecture.md)
- [Experiment 01](docs/kdasa/experiment-01.md)
- [Experiment 02](docs/kdasa/experiment-02.md)
- [Milestone 02](docs/kdasa/milestone-02.md)
- [Milestone 03](docs/kdasa/milestone-03.md)

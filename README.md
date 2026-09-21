# EDR Research Lab

A defensive security research repository focused on Windows endpoint telemetry, kernel visibility, and detection engineering.

## Research modules

- **KDASA — Kernel Driver Attack Surface Analyzer**
  - Read-only kernel telemetry
  - Process/thread/image notifications
  - User-mode ETW collection
  - Driver inventory
  - Offline event analysis
  - PE/security-property extraction
  - Evidence-based review scoring

The repository deliberately avoids security-product tampering, arbitrary kernel memory access, code injection, and operational EDR bypass tooling.

## KDASA status

### Milestone 1 — Kernel telemetry
Documented process, thread, and image-load callbacks in the research driver.

### Milestone 2 — Dual-sensor telemetry
A .NET ETW collector captures process, thread, and image-load events into JSONL. A Python CLI summarizes captured telemetry.

### Milestone 3 — Driver inventory
A PowerShell collector inventories running drivers, versions, publishers, paths, and Authenticode status.

### Milestone 4 — Offline PE analysis and scoring
The analyzer extracts architecture, sections, PE security-directory presence, ASLR/NX/CFG-related flags, writable+executable sections, hashes, and review-priority evidence.

## Documentation

- [KDASA overview](docs/kdasa/README.md)
- [Architecture](docs/kdasa/architecture.md)
- [Experiment 01](docs/kdasa/experiment-01.md)
- [Experiment 02](docs/kdasa/experiment-02.md)
- [Telemetry correlation](docs/kdasa/telemetry-correlation.md)
- [Milestone 02](docs/kdasa/milestone-02.md)
- [Milestone 03](docs/kdasa/milestone-03.md)
- [Milestone 04](docs/kdasa/milestone-04.md)
- [Roadmap](docs/kdasa/roadmap.md)

## Tools

- tools/KdasaCollector — Windows kernel ETW collector
- tools/Get-KdasaDriverInventory.ps1 — running-driver inventory
- tools/kdasa_pe.py — offline PE property extraction
- tools/kdasa_score.py — evidence-based triage scoring
- tools/kdasa_analyze.py — JSONL telemetry analysis

All live kernel work should be performed in a disposable Windows research VM.

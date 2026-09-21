# EDR Research Lab

A defensive security research repository focused on Windows endpoint telemetry, kernel visibility, and detection engineering.

## Research modules

- **EDDRR Training EDR** — intentionally flawed local endpoint-detection simulator with 10 engineered false-negative cases and reproducible PoCs.

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

### Milestone 5 — Static reporting and workload experiments
Added self-contained HTML reporting plus a benign process-stress workload for repeatable telemetry coverage measurements.

### Milestone 6 — Cross-source correlation
Added an offline correlator that matches events by identity plus timestamp tolerance and reports matched/unmatched coverage.

### Milestone 7 — Evidence store
Added a local SQLite backend and query tool for retaining normalized events and original JSON payloads across repeated lab runs.

### Milestone 8 — Advisory correlation
Added provenance-aware exact hash, filename/version, and vendor/product/version advisory matching.

### Milestone 9 — Vulnerable-driver blocklist evidence
Added a local XML blocklist SHA-256 matcher that clearly distinguishes an exact snapshot match from absence of evidence.

### Milestone 10 — Unified assessment
Added a JSON assessment bundle that combines inventory, PE, advisory, blocklist, and scoring artifacts.

### Milestone 11 — Before/after comparison
Added longitudinal comparison of driver identity, signature, PE mitigations, blocklist state, and review-priority evidence.

### Milestone 12 — Driver source security linting
Added heuristic static checks for IOCTL surfaces, user-buffer handling, memory mapping, unsafe string/copy routines, named devices, and debug output.

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
- [EDR evasion research map](docs/edr-evasion-research-map.md)

## Tools

- tools/KdasaCollector — Windows kernel ETW collector
- tools/Get-KdasaDriverInventory.ps1 — running-driver inventory
- tools/kdasa_pe.py — offline PE property extraction
- tools/kdasa_score.py — evidence-based triage scoring
- tools/kdasa_analyze.py — JSONL telemetry analysis
- tools/kdasa_correlate.py — cross-source correlation
- tools/kdasa_db.py — SQLite evidence store
- tools/kdasa_query.py — evidence queries
- tools/kdasa_report.py — static HTML reporting
- tools/kdasa_advisory_match.py — advisory matching
- tools/kdasa_blocklist.py — blocklist hash comparison
- tools/kdasa_assess.py — unified assessment bundle
- tools/kdasa_compare.py — before/after comparison
- tools/kdasa_driver_lint.py — driver source security linting

All live kernel work should be performed in a disposable Windows research VM.

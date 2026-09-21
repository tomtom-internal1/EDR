# A07 — AMSI multi-path validation

Standalone Windows research project.

## Build
```powershell
.\build.ps1
```

CMake:
```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

## Run
```powershell
.\run.ps1
```

Telemetry: `artifacts\\events.jsonl`.

## Research focus

AMSI multi-path validation. Compare multiple independent observations where possible and treat anomalous telemetry as evidence to investigate, not automatic proof of a particular bypass.

## Platform

Windows 10+

## Safety

Local benign experiment only. No AMSI patching, provider disabling, remote process access, payload execution, security-product modification, kernel-memory modification, credential access, or remote network connection.

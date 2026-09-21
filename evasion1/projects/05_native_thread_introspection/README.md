# A05 — Native thread-start provenance

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

Native thread-start provenance. The scenario emphasizes independent ground truth rather than trusting a single user-mode event source.

## Safety

Local benign experiment only. No remote process access, payload execution, security-product tampering, kernel-memory modification, credential access, or remote network connection.

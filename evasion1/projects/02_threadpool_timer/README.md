# A02 — Threadpool timer execution

This folder is a completely standalone Windows research project. Compile and test it without building the other Evasion1 projects.

## Behavior
Threadpool timer execution

The executable produces structured JSONL containing PID/TID identity, sequence numbers, timestamps, lifecycle events, and a detection oracle.

## Build

MSVC:
```powershell
.\build.ps1
```

CMake:
```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Direct:
```text
cl.exe /nologo /std:c11 /W4 /WX /O2 /EHsc main.c /Fe:bin\\02_threadpool_timer.exe
```

## Run

```powershell
.\run.ps1
```

Telemetry is written to `artifacts\\events.jsonl`.

## Detection focus

Correlate lifecycle, PID/TID identity, timing and provenance. Do not require one API name to be present.

## Safety

Local benign research only. No remote process access, payload execution, security-product tampering, kernel-memory modification, credential access, or remote network connection.

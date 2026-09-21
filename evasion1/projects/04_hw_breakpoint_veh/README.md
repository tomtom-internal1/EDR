# A04 — VEH + hardware-breakpoint self-instrumentation

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

Output: `artifacts\\events.jsonl`.

## Research focus

VEH + hardware-breakpoint self-instrumentation. Reconstruct the execution lifecycle from callback registration, process/thread identity, timing, and provenance rather than depending on a single event.

## Architecture

x64 recommended; debug-register layout is architecture-sensitive

## Safety

Local benign experiment. No payload execution, remote process access, security-product tampering, kernel memory modification, credential access, or remote network connection.

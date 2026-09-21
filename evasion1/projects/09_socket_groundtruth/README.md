# A09 — IPv4/IPv6 socket PID ground truth

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

IPv4/IPv6 socket PID ground truth. Reconcile endpoint ownership, lifecycle state, and address-family or callback context instead of relying on one collection path.

## Safety

Local benign experiment only. No remote process access, payload execution, security-product tampering, kernel-memory modification, credential access, or remote network connection to non-loopback destinations.

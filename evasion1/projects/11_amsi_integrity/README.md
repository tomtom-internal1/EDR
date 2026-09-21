# A11 — Live-vs-disk AMSI code integrity

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

Resolve the live `AmsiScanBuffer` export, obtain a second disk-backed image of the same Windows `amsi.dll`, compare a fixed code window, and hash both windows. A mismatch is an integrity anomaly to investigate—not automatic proof of a particular bypass.

## Platform

Windows 10 and later. Windows 11 is recommended for the version-matrix portion of the lab.

## Safety

This project does not patch AMSI, disable a provider, change code bytes, or execute arbitrary content. It only observes and compares the live function with a same-system disk image.

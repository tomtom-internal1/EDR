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

Baseline benign run:

```powershell
.\run.ps1
```

Optional external validation input:

```powershell
.\run.ps1 -InputFile .\validation-input.txt
```

The repository does **not** embed a known AMSI test signature in the C source. Put any vendor-documented validation input in a local file inside your isolated test VM and pass that file with `-InputFile`.

Telemetry: `artifacts\\events.jsonl`.

## Research focus

AMSI multi-path validation. The harness compares observations from `AmsiScanString`, `AmsiScanBuffer`, and `AmsiNotifyOperation`. The buffer path supports either a built-in benign value or an operator-supplied local file.

A detection discrepancy is an investigation signal, not proof of a particular bypass.

## Platform

Windows 10+

## Safety

Local benign experiment only. No AMSI patching, provider disabling, remote process access, payload execution, security-product modification, kernel-memory modification, credential access, or remote network connection.

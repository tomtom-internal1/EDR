# Evasion1 — Advanced Windows Detection Research PoCs

Evasion1 is a ten-scenario Windows research suite derived from the uploaded EDR detection-surface taxonomy.

The exercises are benign and non-operational. They exercise legitimate Windows APIs where practical, but never inject payloads, patch security products, alter kernel callback tables, disable ETW/AMSI, modify PPL state, or perform remote execution.

## Ten scenarios

| ID | Technique | Primary surface | Core detection question |
|---|---|---|---|
| P01 | syscall-path visibility | user-mode API + kernel-origin telemetry | Can detection rely on API-hook visibility alone? |
| P02 | parent-process context | process creation / lineage | Does reported parent context agree with observed lineage? |
| P03 | APC execution | thread + execution context | Can execution through an existing thread be correlated? |
| P04 | timer callback execution | callback + thread context | Is deferred callback execution correlated with registration? |
| P05 | memory protection transition | virtual memory telemetry | Does RW to RX stand out as a lifecycle? |
| P06 | DLL loading context | image-load + filesystem | Is module provenance checked against path context? |
| P07 | ETW degradation | telemetry integrity | Does missing telemetry become a finding instead of silence? |
| P08 | IPv6 network telemetry | WFP/network | Are address families normalized consistently? |
| P09 | local IPC | named pipes + registry | Can local process communication be detected without network events? |
| P10 | kernel sensor integrity | kernel telemetry | Can notification loss be distinguished from normal inactivity? |
| P11 | AMSI validation/integrity | AMSI + Defender provider | Can an unexpected AMSI-clean result be surfaced as an integrity anomaly? |

## Build

Use a Visual Studio Developer PowerShell:

    Set-Location .\evasion1
    .\build.ps1

The build uses MSVC cl.exe and produces binaries in bin.

## Run

    .\run-all.ps1

Each executable emits JSONL. Results are stored under artifacts.

## Engineering workflow

Run a scenario, preserve its JSONL, feed it into EDDRR, identify which telemetry source was absent or weakly correlated, remediate the detector, and add a regression assertion.

## Safety boundary

P01 does not issue direct or indirect syscalls.
P02 does not spoof a real process parent.
P03 and P04 execute only benign callbacks.
P05 never executes memory after changing protection.
P06 loads only the supplied benign fixture DLL.
P07 and P10 simulate telemetry loss or integrity changes instead of disabling Windows telemetry.
P08 connects only to the local IPv6 loopback.
P09 uses only local named-pipe and HKCU registry IPC and cleans up.
P10 performs no driver loading or kernel memory modification.
P11 invokes the documented AMSI API and uses a Microsoft-published validation sample; it does not patch AMSI or disable an antimalware provider.

The suite is intended for a disposable Windows research VM and defensive detection engineering.

# Evasion1 Advanced — Windows Behavioral Research Tier

This tier uses real Windows primitives and multi-source observations rather than single synthetic events.

## Scenarios

| ID | Technique | Windows primitive | Research focus |
|---|---|---|---|
| A01 | Early-bird-style APC lifecycle | CreateThread(CREATE_SUSPENDED) + QueueUserAPC + SleepEx | queued work before the normal worker loop |
| A02 | Threadpool timer execution | CreateThreadpoolTimer | callback execution without application-created thread |
| A03 | callback-based execution | EnumWindows | execution through an OS enumeration callback |
| A04 | hardware-breakpoint instrumentation | VEH + DR0/DR7 | patchless interception on a self-owned function |
| A05 | native thread introspection | NtQueryInformationThread | independent thread-start-address provenance |
| A06 | ETW private-session integrity | StartTraceW + ControlTraceW | session lifecycle and health visibility |
| A07 | AMSI multi-path validation | AmsiScanString + AmsiScanBuffer + AmsiResultIsMalware | provider/result consistency |
| A08 | image-section mapping | SEC_IMAGE + MapViewOfFile | image-backed memory provenance |
| A09 | network ground truth | Winsock + GetExtendedTcpTable | PID-bound IPv4/IPv6 reconciliation |
| A10 | wait-callback execution | RegisterWaitForSingleObject | threadpool callback without explicit thread creation |

## Build

Use a Visual Studio Developer PowerShell:

    Set-Location .\evasion1\advanced
    .\build.ps1

The suite is x64-oriented. A04 uses the native debug-register fields when building for x64.

## Run

    .\run-all.ps1

Results are written to the artifacts directory and validated automatically.

## Safety

All scenarios are local and benign. They do not perform remote process access, payload injection, shell execution, security-product patching, ETW disabling/hijacking, AMSI modification, kernel memory modification, credential access, or arbitrary executable-memory payload execution.

A04 observes a hardware breakpoint on a function inside the same executable and clears it after the first hit.
A08 maps the supplied test DLL with SEC_IMAGE and does not execute from the mapping.


## Standalone projects

The canonical compile/test layout is now under `../projects/`. Every advanced scenario is isolated into its own directory with local source, local telemetry header, MSVC build script, CMake project, run/validation script, and scenario metadata.

Start here: `evasion1/projects/README.md`.

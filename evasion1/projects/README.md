# Evasion1 Standalone Projects

Every advanced scenario is now isolated into its own directory. Each project can be compiled and run without building the other projects.

## Project directories

- `01_early_bird_apc`
- `02_threadpool_timer`
- `03_enumwindows_callback`
- `04_hw_breakpoint_veh`
- `05_native_thread_introspection`
- `06_etw_private_session`
- `07_amsi_multipath`
- `08_sec_image_mapping`
- `09_socket_groundtruth`
- `10_wait_callback`
- `11_amsi_integrity`

## Per-project contract

Every directory contains:

`main.c` — implementation
`poc_common.h` — local telemetry helper; no dependency on a shared build artifact
`build.ps1` — direct MSVC build
`run.ps1` — execute and validate JSONL
`CMakeLists.txt` — independent CMake build
`README.md` — technique and engineering notes
`scenario.json` — machine-readable metadata

## Standalone build

From any project:

```powershell
.\build.ps1
.\run.ps1
```

## Master validation

From this folder:

```powershell
.\validate-layout.ps1
.\build-all.ps1
```

The master build script invokes each project's own build script. It does not compile a monolithic binary.

## Design target

The point of the split is reproducible research: each scenario has one source tree, one build, one execution trace, and one documented detection objective.

# KDASA Architecture

## Process telemetry

KDASA registers `PsSetCreateProcessNotifyRoutineEx` to receive process creation and exit notifications. Creation notifications may provide parent-process, image, and command-line information.

## Thread telemetry

KDASA registers `PsSetCreateThreadNotifyRoutine` to observe thread creation and deletion.

## Image telemetry

KDASA registers `PsSetLoadImageNotifyRoutine` to observe executable-image mappings, including user-mode images and kernel-mode images.

## Important limitation

These callbacks are not a complete EDR sensor. A production endpoint sensor would correlate multiple telemetry layers, potentially including ETW, file, registry, network, handle, memory-management, and code-signing signals.

The project therefore treats missing telemetry as a research observation rather than automatically interpreting it as an evasion or bypass.

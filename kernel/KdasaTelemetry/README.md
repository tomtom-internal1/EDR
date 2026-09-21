# KDASA Kernel Telemetry Sensor

A minimal Windows kernel research driver for observing process, thread, and image-load lifecycle events.

## Design constraints

The driver is read-only telemetry. It has no device object, IOCTL surface, arbitrary memory primitives, process injection, callback tampering, or security-product modification.

## Callbacks

- PsSetCreateProcessNotifyRoutineEx
- PsSetCreateThreadNotifyRoutine
- PsSetLoadImageNotifyRoutine

Microsoft recommends keeping these notification routines short and simple and avoiding blocking/IPC work in them.

## Output

Events are emitted with DbgPrintEx using a stable KDASA prefix for the research parser.

## Lab-only

Build and load this driver only inside a disposable Windows VM with kernel debugging enabled.

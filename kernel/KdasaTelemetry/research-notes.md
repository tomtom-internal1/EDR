# Kernel Sensor Research Notes

## Why callbacks?

The Windows process, thread, and image managers expose callback registration points that make lifecycle activity observable without changing process execution.

## Ordering

Do not assume a universal ordering among callback types. Record timestamps in user mode and compare observations empirically.

## Lifetime

Notification structures are only valid for the duration of the callback. Data needed later must be copied before returning.

## Callback hygiene

Keep notification routines small. Slow operations, blocking behavior, IPC, registry access, and complex synchronization should not be performed directly in these callbacks.

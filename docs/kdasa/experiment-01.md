# Experiment 01 — Kernel Telemetry Coverage

## Objective

Measure the coverage, ordering, and context available from process, thread, and image-load notifications.

## Controlled environment

Use a disposable Windows 11 virtual machine with a kernel debugger. Do not deploy experimental kernel drivers to production systems.

## Procedure

1. Start the test VM and kernel-debugging environment.
2. Load the KDASA research driver.
3. Start ordinary benign applications.
4. Record process, thread, and image events.
5. Capture the diagnostic stream.
6. Parse the stream into JSONL.
7. Measure event counts, ordering, and available metadata.
8. Repeat after reboot to compare startup behavior.

## Measurements

- Events/minute
- Process-create to first-image-load ordering
- Availability of image paths
- Availability of command-line data
- Thread creation volume
- System-mode image frequency
- Collection loss or duplication

## Interpretation

A missing event does not necessarily indicate an EDR blind spot. Investigate callback semantics, collection loss, timing, buffering, and whether another telemetry source provides the missing context.

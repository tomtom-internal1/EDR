# EDDRR Manager Guide

## What engineers are proving

The manager does not need to understand kernel internals to evaluate the exercise.

A successful engineer should be able to demonstrate:

**Scenario:** a simulated remote connection or remote execution happens.

**EDDRR defect:** the detection engine misses it because it trusted one weak signal.

**Root cause:** the engineer identifies the exact assumption.

**Fix:** the engineer adds normalization, corroboration, or proper event correlation.

**Evidence:** the engineer reruns the PoC and shows the corrected detector raises the intended alert.

## Ten demonstrations

1. WMI remote execution
2. WinRM remote execution
3. SMB administrative-share activity
4. RDP session context
5. Remote service execution
6. Remote scheduled task
7. PowerShell remote command syntax
8. Windows command shell syntax
9. Remote file transfer
10. Web traffic / C2-style periodicity

## Simple success criterion

Do not judge an engineer by whether the PoC "looked scary."

Judge the result by whether they can explain:

- what telemetry was present,
- what telemetry was ignored,
- why the detector missed it,
- what change closes the gap,
- what new false positives the change might create.

## Lab boundary

The scenarios are generated entirely as synthetic Event/RemoteEvent objects. No remote host is contacted and no command is executed on another machine.

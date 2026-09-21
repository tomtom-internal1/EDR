# Evasion1 Detection Engineering Guide

This guide is the engineer-facing contract for the ten PoCs. The goal is not to detect a magic string; it is to reconstruct behavior from independent telemetry.

## P01 — Syscall path visibility

Expected evidence:
- image identity for ntdll
- API export resolution
- memory allocation/protection operation
- semantic operation record

Failure mode:
- detector assumes an instrumented Win32 API call is the only observation path

Engineering assertion:
- semantic memory-protection behavior must remain attributable even if the user-mode API path is absent

False-positive control:
- ordinary JIT/runtime memory operations should be baselined by process image, region lifetime, and frequency

## P02 — Parent-process context

Expected evidence:
- process PID
- observed parent PID
- independently reported parent PID

Failure mode:
- detector trusts one parent field without reconciliation

Engineering assertion:
- conflicting lineage is a finding when two trustworthy sources disagree

False-positive control:
- account for PID reuse and snapshot timing before declaring impossible ancestry

## P03 — APC execution

Expected sequence:
1. worker thread starts
2. APC is queued to that thread
3. thread enters an alertable wait
4. benign callback executes
5. worker exits

Failure mode:
- detection keys only on thread creation and misses execution scheduled onto an existing thread

Engineering assertion:
- correlate APC queue operation, target TID, alertability, and callback timing

False-positive control:
- common GUI/runtime frameworks use APC-like mechanisms; use target process role and callback provenance

## P04 — Timer callback execution

Expected sequence:
1. timer queue is created
2. callback is registered
3. deferred callback fires
4. timer lifecycle ends

Failure mode:
- detector observes callback execution but has no preceding registration context

Engineering assertion:
- enrich callback events with registration time, owner process, callback address/provenance, and timer lifetime

False-positive control:
- long-lived service processes can legitimately register many timers

## P05 — Memory protection lifecycle

Expected sequence:
1. RW allocation
2. write
3. RX transition
4. restoration
5. release

Failure mode:
- detector evaluates VirtualProtect in isolation

Engineering assertion:
- combine region identity, allocation time, write activity, protection transitions, and release

False-positive control:
- allow known runtime/JIT/compiler patterns only after stable baselining

## P06 — DLL load context

Expected evidence:
- image-load intent
- resolved DLL path
- module load
- exported marker
- unload

Failure mode:
- detector keys only on filename and ignores provenance

Engineering assertion:
- evaluate module path, expected directory, signer/provenance, parent image, and load flags

False-positive control:
- signed application extension modules should remain explainable through install directory and publisher

## P07 — ETW telemetry degradation

Expected sequence:
- provider sequence 100
- provider sequence jumps to 103
- provider resumes at 104

Failure mode:
- missing telemetry is interpreted as no activity

Engineering assertion:
- sequence discontinuities and collector health must be first-class telemetry

False-positive control:
- distinguish ordinary clock gaps from explicit monotonic sequence loss

## P08 — IPv6 telemetry

Expected sequence:
- AF_INET6 listener on ::1
- AF_INET6 connection to ::1
- payload exchange
- close

Failure mode:
- IPv4 and IPv6 are modeled by separate code paths and one path is incomplete

Engineering assertion:
- normalize address family, endpoint, protocol, process, and connection lifecycle into one schema

False-positive control:
- loopback traffic should be classified separately from remote traffic

## P09 — Local IPC

Expected sequence:
- named pipe creation
- local peer opens pipe
- marker transferred
- registry value written/read
- cleanup

Failure mode:
- detector assumes meaningful inter-process communication must traverse a network socket

Engineering assertion:
- correlate named-object handles, process identity, and registry activity across the same host

False-positive control:
- legitimate application IPC is common; privilege, peer identity, object naming, and frequency matter

## P10 — Kernel sensor integrity

Expected sequence:
- baseline says process/thread/image notifications are present
- process events continue
- thread telemetry disappears
- image telemetry continues
- thread telemetry recovers

Failure mode:
- detector interprets a selective sensor gap as ordinary workload inactivity

Engineering assertion:
- model expected event classes and measure source-specific coverage over time

False-positive control:
- require an independent reason that the event class should have occurred before declaring a sensor failure

## Cross-PoC minimum standard

A detector passes Evasion1 only when it can:
- identify the relevant telemetry source
- correlate at least two independent signals where available
- preserve process/thread identity
- handle missing or delayed events explicitly
- distinguish loopback/local activity from remote activity
- explain why the finding is behaviorally suspicious
- retain a regression test that fails on the vulnerable detector and passes after remediation

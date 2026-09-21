# Evasion1 — Skill Mapping

This suite is a defensive translation of techniques documented in the imported EDR-evasion research skill. The source taxonomy identifies multiple detection layers including user-mode hooks, kernel callbacks, ETW, filesystem/image-load telemetry, WFP/network visibility, and memory/execution surfaces. The skill also describes APC, callback, DLL, syscall, network, and kernel-integrity techniques.

| Evasion1 | Research concept represented | EDR surface exercised | Implementation boundary |
|---|---|---|---|
| P01 | direct/alternate syscall visibility research | user-mode API + semantic operation | ntdll export is called normally; no direct-syscall stub |
| P02 | PPID/parent-context research | process lineage | independently reconciles Toolhelp and NtQueryInformationProcess |
| P03 | APC execution variants | thread/APC execution context | self-process, benign callbacks only |
| P04 | timer/callback execution | deferred execution context | timer queue callback, benign function |
| P05 | executable-memory lifecycle | memory allocation/protection | section-backed memory, RW→RX→RW, never executed |
| P06 | DLL sideload/search-order research | image load + path provenance | explicit user-directory policy, benign fixture |
| P07 | ETW integrity research | provider/session telemetry | real EventRegister/EventWrite with intentional sequence gap; no provider disabling |
| P08 | IPv6/WFP visibility research | network telemetry | real TCP over ::1 loopback only |
| P09 | named-pipe/registry IPC | local IPC telemetry | real child process + local named pipe + HKCU, cleanup |
| P10 | callback/sensor-loss research | kernel-sensor integrity | independent ground truth vs simulated mirror loss; no kernel modification |

## Acceptance model

A successful detection implementation should use the behavioral evidence listed in oracles.json, preserve PID/TID identity, tolerate event ordering differences, and explicitly represent telemetry loss.

The goal is to test whether a detector has a blind spot when one visibility layer is incomplete. It is not to reproduce the offensive payloads described in the source material.

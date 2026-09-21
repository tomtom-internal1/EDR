# EDR Evasion Research Map

This document frames common endpoint-evasion research as a telemetry problem.

The project studies the observable behavior and defensive countermeasures. It does not implement operational bypasses.

| Research topic | Why it challenges endpoint visibility | Useful telemetry |
|---|---|---|
| Process injection | Execution may appear under an existing process identity | Process creation, cross-process memory/thread telemetry, image loads |
| Code/data obfuscation | Static signatures can become less useful after transformation | Command line, script telemetry, file creation, entropy/content normalization |
| Trusted binary proxy execution | A signed/native binary may be the visible process while the interesting content is elsewhere | Parent/child process graph, command line, module loads, network activity |
| In-memory execution | File provenance can be weaker when the payload is never represented as a normal file | Image loads, memory-management telemetry, executable-region characteristics |
| Telemetry interference | Missing events can reduce downstream correlation | Service/configuration integrity, ETW health, event-loss counters, independent sensors |
| API-observation differences | Different collection layers see different parts of execution | ETW, kernel callbacks, API telemetry, event correlation |
| Security-control impairment | Disabling or altering defensive components directly affects visibility | Service state, configuration changes, protected-process events, administrative audit |
| Driver abuse research | Kernel-resident code operates below many user-mode observation layers | Driver inventory, signing state, image-load callbacks, vulnerability intelligence |
| Parentage manipulation research | Process trees can become misleading if ancestry is not independently corroborated | Kernel process telemetry, security auditing, token/session context |
| Event-rate stress | High event volume can expose buffering or correlation limitations | ETW lost events, queue depth, timestamps, dropped-event counters |

## Research principle

A "blind spot" should only be declared after ruling out:

1. provider configuration
2. dropped or delayed events
3. timestamp conversion
4. parser limitations
5. callback semantics
6. missing context in the chosen sensor

## Sources

- MITRE ATT&CK T1055 — Process Injection
- MITRE ATT&CK T1027 — Obfuscated Files or Information
- MITRE ATT&CK T1218 — System Binary Proxy Execution
- MITRE ATT&CK T1562 / current Disable or Modify Tools coverage

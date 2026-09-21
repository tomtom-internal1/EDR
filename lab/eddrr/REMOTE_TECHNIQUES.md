# EDDRR Remote-Technique Training Set

The manager-facing vocabulary is intentionally simple: each exercise models a "remote connection" or "remote execution" scenario that a real EDR would be expected to reason about.

These are **simulations**, not attack instructions.

| ID | Technique family | Engineer problem |
|---|---|---|
| R01 | WMI remote execution | Local-vs-remote origin is not corroborated |
| R02 | WinRM | Protocol detection assumes one transport representation |
| R03 | SMB administrative share | Connection telemetry is separated from subsequent file activity |
| R04 | RDP | Session context is insufficiently evaluated |
| R05 | Remote service execution | Create/start/remote-target events are not correlated |
| R06 | Remote scheduled task | Remote task creation is filtered as if only local tasks mattered |
| R07 | PowerShell | One command-line spelling is treated as the whole behavior |
| R08 | Windows Command Shell | Command interpreter matching is case-sensitive |
| R09 | Remote transfer | File extension is treated as transfer identity |
| R10 | Web traffic / C2 simulation | One User-Agent string is treated as a reliable identity |

## Engineer exercise

For every case:

1. Run the synthetic PoC.
2. Identify the exact weak assumption.
3. Add the missing telemetry or normalization.
4. Implement the remediation manually.
5. Add a regression test.
6. Demonstrate that the fixed engine detects the same behavior.
7. Check false positives against benign remote administration fixtures.

The goal is to learn how an EDR should correlate **source host + target host + account + protocol + process + timing + outcome**, rather than rely on one easily-variable field.

## ATT&CK alignment

The vocabulary maps to common ATT&CK categories such as WMI, Remote Services, PowerShell, Command Shell, Scheduled Task/Job, Service Execution, and Application Layer Protocols. The lab intentionally omits operational commands and payloads.

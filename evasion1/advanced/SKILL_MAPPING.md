# Advanced Evasion1 — Skill Mapping

The imported research skill covers user-mode hook visibility, APC and thread variants, callback-based execution, hardware-breakpoint research, ETW/AMSI surfaces, image-loading and memory surfaces, and network/WFP visibility.

This tier translates those concepts into benign Windows experiments.

| PoC | Skill concept | Real Windows exercise | Detection objective |
|---|---|---|---|
| A01 | early-bird APC | suspended worker + queued benign APC + alertable wait | correlate queue-before-resume with execution |
| A02 | threadpool execution | real threadpool timer | identify callback execution without explicit thread creation |
| A03 | callback execution | EnumWindows callback | model OS callback execution as an execution surface |
| A04 | hardware-breakpoint instrumentation | DR0/DR7 + VEH on own function | identify patchless interception without code mutation |
| A05 | native thread inspection | NtQueryInformationThread | reconcile independent thread-start provenance |
| A06 | ETW session research | private logger creation + query + stop | establish trace-session health telemetry |
| A07 | AMSI | ScanString + ScanBuffer + ResultIsMalware + NotifyOperation | cross-check AMSI paths and unexpected clean results |
| A08 | image-backed memory | SEC_IMAGE mapping of benign DLL | correlate file identity with image-backed memory |
| A09 | network visibility | IPv4/IPv6 loopback + TCP owner tables | normalize families and reconcile PID ownership |
| A10 | callback/threadpool blind spot | RegisterWaitForSingleObject | detect deferred callback execution without application thread creation |

The source skill includes offensive patching, AMSI disabling, ETW silencing, callback removal, BYOVD, and process-injection payloads. Those operational portions are intentionally not reproduced. The research invariants are exercised at the observation boundary.

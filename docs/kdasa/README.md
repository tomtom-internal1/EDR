# KDASA — Kernel Driver Attack Surface Analyzer

KDASA is a Windows security-research module for studying kernel telemetry and driver attack-surface characteristics.

## Milestone 1

The first experiment uses documented Windows notification callbacks to observe process creation/exit, thread creation/exit, and executable-image/driver-image loading.

The sensor is intentionally read-only. It does not expose IOCTLs, manipulate kernel memory, inject code, or modify EDR/Defender state.

## Research question

How much endpoint-relevant activity can be reconstructed from these kernel notification streams, and where do gaps arise because of callback semantics, event ordering, or missing context?

## Roadmap

1. Kernel callbacks
2. User-mode collection and timestamps
3. Event correlation
4. Driver PE/signature analysis
5. Vulnerability/CVE correlation
6. Risk scoring
7. Reporting
8. Controlled EDR-visibility experiments

# Milestone 12 — Driver Source Security Linting

KDASA can statically scan driver source code for patterns that warrant manual security review.

The initial rules focus on:

- METHOD_NEITHER
- IRP_MJ_DEVICE_CONTROL
- physical-memory mapping APIs
- user-buffer probing
- raw memory copies
- unbounded C string routines
- named device/symbolic-link creation
- debug-print calls

Microsoft's driver security checklist explicitly recommends threat analysis, secure coding review, CodeQL, Driver Verifier, and review of driver access control. This linter is only a lightweight first-pass aid; it does not replace those tools or a code review.

Source: Microsoft Learn, Driver security checklist.

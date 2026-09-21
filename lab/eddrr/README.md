# EDDRR Training EDR

This directory is an intentionally vulnerable, local-only EDR simulator for engineering review.

Engineers are expected to inspect the source, reproduce the ten failures, identify root cause, implement their own fixes, add regression tests, and demonstrate that the corrected engine closes the gap.

Architecture:

Synthetic endpoint event -> Training Collector -> Vulnerable Detection Engine -> SQLite + Alerts

Safety boundary: the simulator evaluates synthetic Event objects only. It does not inject into processes, modify memory, alter Windows Defender/EDR state, or interact with kernel device interfaces.

Run the PoC suite from this directory:

    python pocs\poc_suite.py

A PASS means the intentionally vulnerable engine reproduced the expected false negative.

Engineer deliverables:

- reproduce the finding
- identify the unsafe assumption
- implement a principled fix manually
- add a regression test
- rerun all ten cases
- document false-positive impact and residual limitations

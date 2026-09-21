# A11 — AMSI Code Integrity

A11 addresses the AMSI bypass research surface from the opposite direction: instead of modifying AMSI, it asks whether a detector can identify a modified AMSI code path.

## Method

1. Obtain the live AmsiScanBuffer address from amsi.dll.
2. Obtain a second image of the same system amsi.dll from the Windows system directory using DONT_RESOLVE_DLL_REFERENCES.
3. Resolve AmsiScanBuffer in both images.
4. Compare a fixed 64-byte code window.
5. SHA-256 hash each window.
6. Report equality or divergence.

## Detection interpretation

A mismatch is an integrity anomaly, not automatic proof of a particular bypass. Legitimate instrumentation, servicing, hotpatching, or unusual loader state can also change code bytes.

A strong EDR implementation should combine this result with:
- file hash and Authenticode identity
- OS build
- AMSI provider health
- AmsiScanBuffer result behavior
- process image identity
- code-page protection state

This gives two independent AMSI tests:
- A07 tests provider semantics.
- A11 tests code integrity.

Together they can distinguish several classes of failure that a single AMSI scan cannot.

## Windows 11

Do not assume a fixed internal offset or a fixed instruction sequence. The test resolves the exported function at runtime and compares the live image against a disk-backed image from the same system.

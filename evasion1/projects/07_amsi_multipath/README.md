# A07 — AMSI multi-path validation

Standalone Windows research project for high-fidelity AMSI measurement and EDR telemetry.

## Build

\`\`\`powershell
.\\build.ps1
\`\`\`

CMake:

\`\`\`powershell
cmake -S . -B build -A x64
cmake --build build --config Release
\`\`\`

## Run

Baseline benign run:

\`\`\`powershell
.\\run.ps1
\`\`\`

Repeat the observation matrix five times:

\`\`\`powershell
.\\run.ps1 -Repeat 5
\`\`\`

Use an operator-supplied local validation input:

\`\`\`powershell
.\\run.ps1 -InputFile .\\validation-input.txt -Repeat 3
\`\`\`

The repository intentionally does not embed a vendor AMSI test signature. A validation input remains outside source control and is supplied at runtime.

## Measurement matrix

Every repetition measures four documented AMSI paths:

\`\`\`text
AmsiScanString  + session
AmsiScanString  + no session
AmsiScanBuffer  + session
AmsiScanBuffer  + no session
\`\`\`

The same benign string is used for the two string-path measurements. The buffer path uses either the built-in benign byte sequence or the exact operator-supplied local file.

For each scan the harness records:

- HRESULT and success state.
- AMSI_RESULT.
- AmsiResultIsMalware interpretation.
- Input size.
- Input SHA-256.
- High-resolution latency.
- Session/no-session mode.
- Repetition number through the event sequence.

It also records the AMSI DLL version context and the result of AmsiNotifyOperation.

Microsoft documents AmsiScanBuffer as the API for scanning a buffer, notes that the optional session correlates multiple scan requests, and recommends AmsiResultIsMalware when interpreting whether content should be blocked. citeturn862137search0turn862137search1

## Detection oracle

A07 deliberately separates **scan detection** from **harness health**.

A sample returning DETECTED is a successful AMSI observation.

The oracle is:

\`\`\`text
STABLE
  all scan calls succeeded
  AND no path changed result across repetitions

ANOMALY
  any scan HRESULT failed
  OR a path changed result across repetitions
\`\`\`

An ANOMALY is an investigation signal. It is not proof of a specific AMSI bypass.

## Telemetry

Output:

\`artifacts\\\\events.jsonl\`

The event stream is JSONL and can be correlated with EDDRR/KDASA telemetry using PID/TID, sequence numbers, and timestamps.

## Platform

Windows 10+

## Safety

Local research only. No AMSI patching, provider disabling, process injection, remote process access, payload execution, security-product tampering, kernel-memory modification, credential access, or remote network connection.

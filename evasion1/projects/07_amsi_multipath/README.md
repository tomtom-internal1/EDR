# A07 — AMSI multi-path validation

Standalone Windows research project for high-fidelity AMSI measurement and EDR correlation.

## Two execution tiers

**Native integration**
- Calls the documented AMSI interfaces on Windows.
- Measures real provider behavior, HRESULTs, AMSI results, session behavior, and latency.

**Deterministic simulator**
- Does not call AMSI.
- Does not touch process memory or security products.
- Generates controlled telemetry anomalies so EDR logic can be regression-tested even when Windows security controls block the native research source.
- Every simulated event is explicitly marked \`"simulation":true\`.

This separation is deliberate: simulated observations are never presented as real AMSI observations.

## Build

\`\`\`powershell
.\\build.ps1
\`\`\`

CMake:

\`\`\`powershell
cmake -S . -B build -A x64
cmake --build build --config Release
\`\`\`

The build produces:

\`\`\`text
bin\\07_amsi_multipath.exe
bin\\07_amsi_multipath_sim.exe
\`\`\`

## Native run

\`\`\`powershell
.\\run.ps1 -Mode Native
\`\`\`

Repeat the observation matrix five times:

\`\`\`powershell
.\\run.ps1 -Mode Native -Repeat 5
\`\`\`

Use an operator-supplied local validation input:

\`\`\`powershell
.\\run.ps1 -Mode Native -InputFile .\\validation-input.txt -Repeat 3
\`\`\`

The repository does not embed a vendor AMSI test signature. Validation input stays outside source control.

## Deterministic regression tests

Baseline:

\`\`\`powershell
.\\run.ps1 -Mode Simulator -Scenario stable -Repeat 3
\`\`\`

Force result instability:

\`\`\`powershell
.\\run.ps1 -Mode Simulator -Scenario result-flip -Repeat 3
\`\`\`

Force an HRESULT failure:

\`\`\`powershell
.\\run.ps1 -Mode Simulator -Scenario hresult-failure -Repeat 3
\`\`\`

Force cross-path drift:

\`\`\`powershell
.\\run.ps1 -Mode Simulator -Scenario cross-path-drift -Repeat 3
\`\`\`

Expected simulator oracle:

\`\`\`text
stable             -> STABLE
result-flip        -> ANOMALY
hresult-failure    -> ANOMALY
cross-path-drift   -> ANOMALY
\`\`\`

## Measurement matrix

The native harness repeats:

\`\`\`text
AmsiScanString  + session
AmsiScanString  + no session
AmsiScanBuffer  + session
AmsiScanBuffer  + no session
\`\`\`

For each scan it records HRESULT, AMSI_RESULT, AmsiResultIsMalware, input size, input SHA-256, latency, and session state. It also records AMSI DLL version context and AmsiNotifyOperation.

Microsoft documents AmsiScanBuffer for buffer scanning, the optional session for correlating scan requests, and AmsiResultIsMalware for interpreting results. citeturn862137search0turn862137search1

## Detection oracle

**STABLE**
- all native scan HRESULTs succeeded
- no measured path changed result across repetitions

**ANOMALY**
- any native scan HRESULT failed
- or repeated results changed

An ANOMALY is an investigation signal, not proof of a specific bypass.

## Telemetry

Output:

\`artifacts\\\\events.jsonl\`

Native events contain real PID/TID values. Simulator events use \`pid=0\`, \`tid=0\`, and \`simulation=true\` so downstream correlation can distinguish synthetic control traffic.

## Safety

Local research only. No AMSI patching, provider disabling, process injection, remote process access, payload execution, security-product tampering, kernel-memory modification, credential access, or remote network connection.

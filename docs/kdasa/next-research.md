# Next EDR Research

After the telemetry foundation is validated, research should proceed as controlled comparisons:

1. Process injection visibility — compare benign cross-process operations with kernel and ETW telemetry, without implementing payload execution.
2. Obfuscation visibility — compare semantically equivalent benign commands before and after harmless string transformations.
3. Trusted-binary execution — measure process-tree and module-load signals for ordinary signed Windows binaries.
4. Memory provenance — study how executable mappings differ between normal applications and controlled test binaries.
5. Telemetry integrity — intentionally introduce collection-side packet loss or parser omissions and measure detection degradation.
6. Driver attack surface — combine inventory, PE properties, signing metadata, and public advisories.

Each study should publish its hypothesis, controlled variable, expected telemetry, observations, limitations, and defensive conclusion.

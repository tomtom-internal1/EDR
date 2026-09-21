# Milestone 09 — Vulnerable Driver Blocklist Evidence

KDASA can compare a driver SHA-256 against a locally supplied XML blocklist snapshot.

## Important interpretation

The result is only an exact-hash comparison against the supplied snapshot. A negative result does not prove that a driver is safe, because blocklists are curated datasets and can lag newly discovered vulnerabilities.

Microsoft states that its vulnerable driver blocklist is enabled by default on Windows 11 2022 Update devices, is updated quarterly, and can receive additional servicing updates. Microsoft also notes the list is not guaranteed to cover every vulnerable driver.

Source: Microsoft Learn — Microsoft recommended driver block rules.

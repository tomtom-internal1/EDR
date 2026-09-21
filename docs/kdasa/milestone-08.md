# Milestone 08 — Advisory Correlation

KDASA supports an offline advisory catalog with provenance.

## Match hierarchy

1. Exact SHA-256 match
2. Driver filename + exact version
3. Vendor + product + exact version

The resulting confidence field distinguishes a cryptographic identity match from metadata matching.

## Why offline-first?

Public vulnerability data changes over time. Keeping the adopted catalog separate from the analyzer makes each report reproducible because the report can identify the exact catalog version used.

## Microsoft vulnerable driver blocklist

For the live lab, treat Microsoft's vulnerable driver blocklist as a separate evidence source. Microsoft states that the blocklist is enabled by default on Windows 11 2022 Update devices, is updated quarterly, and can also receive updates through monthly Windows servicing. Microsoft also notes that the blocklist is not guaranteed to include every vulnerable driver.

Source: Microsoft Learn, "Microsoft recommended driver block rules".

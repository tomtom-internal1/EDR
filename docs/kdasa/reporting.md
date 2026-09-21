# KDASA Reporting

The static reporter intentionally stores the JSON evidence blocks inside the HTML artifact. This keeps the result reviewable without a service backend.

For sensitive lab data, store reports outside public repositories because command lines, paths, and certificate subjects may contain local identifiers.

A future web UI should preserve the same evidence-first structure and should not suppress raw source context merely to present a cleaner risk score.

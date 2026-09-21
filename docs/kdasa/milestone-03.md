# Milestone 03 — Driver Inventory and Offline Risk Inputs

The project now has a read-only inventory script for running Windows system drivers.

## Inventory fields

- Driver service name
- Display name
- State and start mode
- Raw and resolved path
- File/product version
- Company
- Authenticode status
- Signer subject

## Why this matters

Driver attack-surface research needs an accurate asset inventory before deeper inspection. The inventory stage is deliberately non-invasive: it reads system metadata and file signatures without opening driver interfaces or attempting exploitation.

## Follow-on analysis

Future milestones can add offline PE parsing, import/export summaries, mitigation metadata, and public vulnerability correlation.

# Gatecheck Bundle

Gatecheck bundles multiple security reports into a single .gcb file for easy sharing and attestation.

## Commands

- `gatecheck bundle new bundle.gcb`: Create a new bundle.
- `gatecheck bundle add bundle.gcb report.json --type grype`: Add a report.
- `gatecheck bundle list bundle.gcb`: List contents.

Bundles can include metadata and multiple report types.
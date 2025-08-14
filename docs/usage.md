# Usage

Gatecheck is a lightweight CLI utility for handling security reports. It allows bundling reports, listing their contents, validating against configurations, and more.

Developers can use it to summarize reports, run local audits, cross-reference with EPSS and KEV, and bundle reports for attestation.

Run `gatecheck --help` for available commands.

Key commands:
- `gatecheck bundle`: Bundle reports into a .gcb file.
- `gatecheck config`: Generate or manage config files.
- `gatecheck list`: List contents of reports or bundles.
- `gatecheck validate`: Validate reports against config.
- `gatecheck download`: Download EPSS or KEV data.

See CLI Reference for details.
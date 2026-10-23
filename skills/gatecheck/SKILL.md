---
name: gatecheck
description: Use when running gatecheck to list, validate, or bundle scanner reports, or when writing a gatecheck config.
---

# gatecheck

Run `gatecheck agent-guide` and follow that output. The alias is `gatecheck llm`.

`gatecheck bootstrap` can install Trivy, and a filename containing `trivy` is a Trivy JSON report. Severity limits and CVE allow and deny lists use the same fields as Grype.

The command prints `docs/agent-guide.md`. That file is embedded in the binary, so the command and the file are the same text. Prefer the command when the `gatecheck` binary is installed.

If you are changing this repository, read `AGENTS.md` instead.

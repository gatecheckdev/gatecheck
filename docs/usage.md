# Usage

Gatecheck is a lightweight CLI for security reports. It summarizes a report, checks it against a config, downloads EPSS and KEV data, and packs reports into one bundle.

Running `gatecheck` with no arguments prints nothing and exits 0. `gatecheck --help` lists the commands. `gatecheck config`, `gatecheck bundle`, and `gatecheck download` print the help for their subcommands.

Commands:

- `gatecheck version` prints the build information. `gatecheck --version` does the same. The `--version` flag is only on the root command.
- `gatecheck config init` prints a default config. `gatecheck config convert` rewrites one into another format.
- `gatecheck list` (aliases `ls` and `print`) prints one report. `gatecheck list-all` prints several.
- `gatecheck validate` compares one report, or one bundle, to the config.
- `gatecheck bundle create`, `bundle add`, and `bundle remove` manage a bundle.
- `gatecheck download epss` and `gatecheck download kev` write the upstream data to standard output. EPSS files are cached until the published date changes.
- `gatecheck bootstrap` installs Grype, Syft, Gitleaks, semgrep's experimental osemgrep CLI, Trivy, and osv-scanner. `gatecheck grype`, `syft`, `gitleaks`, `semgrep`, `osemgrep`, `trivy`, and `osv-scanner` run those programs. See [Bootstrap](./bootstrap.md).
- `gatecheck update` (aliases `self-update` and `upgrade`) replaces this binary with a GitHub release after checking the archive checksum. `gatecheck update --check` only prints the current and latest versions.
- `gatecheck agent-guide` (alias `llm`) prints a markdown guide for coding agents.
- `gatecheck completion` prints a shell completion script. `gatecheck help [command]` prints help for that command.

`list` and `validate` decide the report type from the file contents. The filename is the fallback when the contents are ambiguous. See [Supported Reports](./supported-reports.md).

Logs go to standard error. Tables, downloaded data, and `config init` go to standard output.

Exit status:

- `0` when the command succeeds. With `validate --audit`, an error returned by the check also exits 0.
- `1` when a report misses a configured threshold and `--audit` is off.
- `255` for a missing file, a rejected command line, or a check error when `--audit` is off.
- The scanner commands return that program's own status. A scanner that is neither installed nor on `PATH` exits 255.

[Validation](./validation.md) lists which `validate` failures are which status.

`--verbose` (`-v`) prints debug logs. `--silent` hides debug, info, and warning logs, and errors are still printed. The two flags cannot be used together. They are available on every command.

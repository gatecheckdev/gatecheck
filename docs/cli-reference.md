# CLI Reference

Global flags, accepted on every command:

- `-v`, `--verbose`: print debug logs. The same as `--log-level debug`. `GATECHECK_VERBOSE=true` is the same setting.
- `--silent`: print only warnings and errors. The same as `--log-level warn`. `GATECHECK_SILENT=true` is the same setting.
- `--log-level`: `debug`, `info`, `warn`, or `error`. The default is `info`. `GATECHECK_LOG_LEVEL` is the same setting.
- `--log-format`: `text` or `json`. The default is `text`, colored only when standard error is a terminal and `NO_COLOR` is unset. `GATECHECK_LOG_FORMAT` is the same setting.
- `-h`, `--help`: help for that command.

`--verbose`, `--silent`, and `--log-level` cannot be set together. A flag wins over any of the variables. Among the variables, `GATECHECK_VERBOSE` and `GATECHECK_SILENT` win over `GATECHECK_LOG_LEVEL`, and setting both of them to true is an error.

Every setting is read in the same order: a flag on the command line, then its environment variable, then the default. An empty environment variable counts as unset. Boolean variables take `true`, `false`, `1`, `0`, `t`, or `f`. Any other value is a usage error, and the command exits 2.

## Exit status

- `0`: success.
- `1`: `validate` found a threshold failure.
- `2`: a usage error, a file that could not be read or written, or a report, config, or VEX file that could not be decoded.
- `3`: EPSS or KEV data could not be downloaded or read.
- The scanner commands (`grype`, `syft`, `gitleaks`, `semgrep`, `osemgrep`, `trivy`, `osv-scanner`, `gosec`, `hadolint`, `zizmor`) return the scanner's own status.

`validate --audit` turns status 1 into 0. It does not change 2 or 3.

## gatecheck

```
gatecheck [flags]
gatecheck [command]
```

With no arguments, the command prints nothing and exits 0.

- `--version`: print the same build information as `gatecheck version`. This flag is only on the root command.

## gatecheck version

```
gatecheck version
```

Prints the logo and the build information: CLI version, git commit, build date, git description, platform, Go version, and compiler. A build that does not pass those values prints `[Not Provided]`.

## gatecheck config init

```
gatecheck config init
```

Prints a default config to standard output. Every rule is disabled and every coverage threshold is `0`. JSON and YAML are indented by two spaces, and TOML tables are indented.

- `-o`, `--output`: `json`, `toml`, `yaml`, or `yml`, with or without a leading dot, in any case. The default is `yaml`. Any other value is an error.

```shell
gatecheck config init > gatecheck.yaml
gatecheck config init --output json > gatecheck.json
```

## gatecheck config convert

```
gatecheck config convert
```

Reads a config file and prints it in another format. Keys gatecheck does not read are named in a warning and left out of the output.

- `-f`, `--file`: file to read. The default is `gatecheck.yaml`. The extension picks the decoder (`.yaml`, `.yml`, `.json`, `.toml`).
- `-o`, `--output`: format to write. Same accepted values as `config init`. The default is `yaml`.

```shell
gatecheck config convert --file gatecheck.yaml --output toml
```

## gatecheck list

```
gatecheck list [FILE]
```

Aliases: `ls`, `print`.

Prints a table for one report. Use `list-all` for more than one file. A Grype, CycloneDX, SARIF, Semgrep, Gitleaks, Trivy, osv-scanner, or Syft report with nothing in it prints one sentence and no table: `No grype vulnerabilities`, `No cyclonedx vulnerabilities`, `No sarif findings`, `No semgrep findings`, `No gitleaks findings`, `No trivy vulnerabilities`, `No osv-scanner vulnerabilities`, or `No syft packages`. Markdown prints that same sentence.

The report type comes from the file contents. See [Supported Reports](./supported-reports.md).

With no filename, the command reads standard input and `--input-type` is required.

- `-i`, `--input-type`: type word used when the contents are ambiguous, and the type of standard input. It is matched with the same rules as a filename. `grype`, `cyclonedx`, `sarif`, `semgrep`, `gitleaks`, `trivy`, `osv`, `syft`, `bundle`, and the coverage words `lcov`, `clover`, and `cobertura` all work. Clear contents win over this flag. See [Supported Reports](./supported-reports.md).
- `--format`: `table` (the default), `markdown`, or `json`. JSON is `{"columns": [...], "rows": [{column: value}], "footer": {...}}`. A report with nothing in it is `{"columns": [], "rows": [], "message": "No grype vulnerabilities"}`. A bundle is its manifest.
- `--markdown`: the same as `--format markdown`. It cannot be combined with another `--format`.
- `--epss`: add EPSS score and percentile columns. This changes the table for Grype, CycloneDX, Trivy, and osv-scanner. Other report types still list, and the EPSS data is not shown. With no local file, gatecheck downloads the current EPSS CSV and caches it until the published date changes. Requests send a User-Agent with the gatecheck version and project URL.
- `--epss-filename`: read that CSV instead of calling the API. `GATECHECK_EPSS_FILENAME` is the same setting.
- `--epss-url`: EPSS API URL. An empty value uses `https://epss.cyentia.com`. `GATECHECK_EPSS_URL` is the same setting.
- `--epss-cache-dir`: cache directory for that download. `GATECHECK_EPSS_CACHE_DIR` is the same setting.
- `--epss-no-cache`: download on every run. `GATECHECK_EPSS_CACHE=off` does the same.

A failed EPSS download or an unreadable EPSS file exits 3.

```shell
gatecheck list grype-report.json
gatecheck list --format markdown --epss grype-report.json
gatecheck list --format json trivy-report.json
grype bkimminich/juice-shop:latest -o json | gatecheck ls --input-type grype
```

## gatecheck list-all

```
gatecheck list-all FILE...
```

Prints each filename, then its table, or one sentence when that report has nothing in it. A file whose contents and name are not a supported `list-all` type is skipped with a warning. Coverage files are in that skipped set. A file that cannot be read or listed is logged and the command goes on to the next one. When any file could not be read or listed, the command exits 2 after the last file. At least one file is required.

- `--format`: `table`, `markdown`, or `json`. JSON is one array: `[{"file": "grype-report.json", "report": {...}}]`, where `report` is what `list --format json` prints. Skipped files are not in the array.
- `--markdown`: the same as `--format markdown`.
- `--epss`: add EPSS data for Grype, CycloneDX, Trivy, and osv-scanner reports. The type comes from the file contents, then the filename. EPSS data is loaded once, the first time a file needs it.
- `--epss-filename`, `--epss-url`, `--epss-cache-dir`, and `--epss-no-cache`: the same as on `list`, with the same environment variables.

## gatecheck validate

```
gatecheck validate [FILE]
```

`FILE` is the report or bundle. With no `FILE`, `--input-type` is required, and the report is read from standard input. The config is a flag.

- `-f`, `--config`: config file. `GATECHECK_CONFIG_FILENAME` is the same setting. With neither, the built-in default config is used (every rule disabled, coverage thresholds `0`), and a warning says so. Keys in the config that gatecheck does not read are named in a warning, and the rest of the file is still used.
- `-i`, `--input-type`: report type word, the same as on `list`. It is used when the contents are ambiguous, and it is required when reading standard input.
- `-a`, `--audit`: print a threshold failure and exit 0. Any other error still fails: a missing report or config is 2, and an EPSS or KEV fetch failure is 3. `GATECHECK_AUDIT` is the same setting.
- `--format`: also print the result to standard output as `table`, `markdown`, or `json`. With no `--format`, standard output is empty. JSON is `{"report": "grype-report.json", "passed": false, "failures": ["Grype: Severity Limit Exceeded"]}`, plus `"error"` when the check stopped on something other than a threshold.
- `--vex`: OpenVEX or CycloneDX VEX file. Findings it marks not exploitable are skipped. Repeat the flag for more files. `GATECHECK_VEX` is a comma-separated list used when the flag is absent. Files in the config's `vex.files` are read too. A VEX file that cannot be read exits 2. See [VEX](./vex.md).
- `--epss-filename`: EPSS CSV to use when an EPSS rule is enabled. `GATECHECK_EPSS_FILENAME` is the same setting.
- `--epss-url`: EPSS feed URL. `GATECHECK_EPSS_URL` is the same setting.
- `--epss-cache-dir`: cache directory used when that CSV is downloaded. `GATECHECK_EPSS_CACHE_DIR` is the same setting.
- `--epss-no-cache`: download on every run. `GATECHECK_EPSS_CACHE=off` does the same.
- `--kev-filename`: CISA KEV JSON to use when a KEV rule is enabled. `GATECHECK_KEV_FILENAME` is the same setting.
- `--kev-url`: KEV feed URL. `GATECHECK_KEV_URL` is the same setting.

EPSS data is loaded only when an EPSS limit or EPSS risk acceptance rule is enabled. When `--epss-filename` is not set, gatecheck downloads the current EPSS file and caches it until the published date changes. Requests send a User-Agent with the gatecheck version and project URL.

KEV data is loaded only when `kevLimitEnabled` is true for Grype, CycloneDX, Trivy, or osv-scanner.

```shell
gatecheck validate --config gatecheck.yaml grype-report.json
gatecheck validate --audit --config gatecheck.yaml gatecheck-bundle.tar.gz
```

See [Validation](./validation.md) for rule order and exit codes.

## gatecheck bundle create

```
gatecheck bundle create BUNDLE_FILE TARGET_FILE
```

Alias: `init`.

Creates a bundle and stores the target file in it. An existing `BUNDLE_FILE` is replaced. The label is the base name of the target file (`reports/grype-report.json` is stored as `grype-report.json`).

- `-t`, `--tag`: tag stored on that file. Repeat the flag for more than one tag. `GATECHECK_BUNDLE_TAG` is a comma-separated list used when no tag flag is passed.

```shell
gatecheck bundle create gatecheck-bundle.tar.gz grype-report.json --tag ci
```

## gatecheck bundle add

```
gatecheck bundle add BUNDLE_FILE TARGET_FILE
```

Adds another file to an existing bundle. The label is the base name of the target file. `--tag` and `GATECHECK_BUNDLE_TAG` work the same way as on `bundle create`.

## gatecheck bundle remove

```
gatecheck bundle remove BUNDLE_FILE LABEL
```

Alias: `rm`.

Deletes the file with that label. The label is the base name used when the file was added, not a path that is opened. A label that is not in the bundle is an error: the bundle is left as it was and the command exits 2.

## gatecheck download epss

```
gatecheck download epss
```

Writes the FIRST.org EPSS CSV to standard output.

EPSS scores are cached in the user cache directory, under `gatecheck/epss`. gatecheck checks the redirect to the dated filename and downloads the CSV only when that file is not already cached. Requests send a User-Agent with the gatecheck version and project URL.

- `--epss-url`: API URL. An empty value uses `https://epss.cyentia.com`. `GATECHECK_EPSS_URL` is the same setting.
- `--epss-cache-dir`: cache directory. `GATECHECK_EPSS_CACHE_DIR` is the same setting.
- `--epss-no-cache`: download on every run. `GATECHECK_EPSS_CACHE=off` does the same.

A failed download exits 3.

```shell
gatecheck download epss > epss.csv
```

## gatecheck download kev

```
gatecheck download kev
```

Writes the CISA Known Exploited Vulnerabilities catalog as JSON to standard output.

- `--kev-url`: API URL. An empty value uses `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. `GATECHECK_KEV_URL` is the same setting.

A failed download exits 3.

```shell
gatecheck download kev > kev.json
```

## gatecheck bootstrap

```
gatecheck bootstrap
```

Downloads Grype, Syft, Gitleaks, semgrep's experimental osemgrep CLI, Trivy, and osv-scanner into the gatecheck data directory. gosec, hadolint, and zizmor are installed when named in `--tools`. Each GitHub asset is checked against the project's SHA-256 checksum file. zizmor publishes none, so its digests are compiled into gatecheck. The semgrep wheel is checked against the digest in the PyPI JSON. A tool already at the pinned version is skipped. See [Bootstrap](./bootstrap.md).

- `--tools`: comma-separated scanners. Default `grype,syft,gitleaks,semgrep,trivy,osv-scanner`. Also accepts `gosec`, `hadolint`, and `zizmor`. `osemgrep` selects semgrep.
- `--force`: download again when the pinned version is already installed.
- `--list`: print pinned version, installed version, and path for every supported tool, or for the `--tools` set. This does not download.

`GATECHECK_HOME` is the data directory. Binaries are in its `bin` subdirectory.

```shell
gatecheck bootstrap
gatecheck bootstrap --list
```

## gatecheck grype, syft, gitleaks, semgrep, osemgrep, trivy, osv-scanner, gosec, hadolint, zizmor

```
gatecheck grype [scanner arguments]
gatecheck syft [scanner arguments]
gatecheck gitleaks [scanner arguments]
gatecheck semgrep [scanner arguments]
gatecheck osemgrep [scanner arguments]
gatecheck trivy [scanner arguments]
gatecheck osv-scanner [scanner arguments]
gatecheck gosec [scanner arguments]
gatecheck hadolint [scanner arguments]
gatecheck zizmor [scanner arguments]
```

Runs the managed binary. Arguments and streams are passed through, and the process exits with the scanner's status. Flags after the command name are not parsed by gatecheck, so `gatecheck grype --help` is Grype's help.

The managed copy is preferred. If it is absent, the same tool name on `PATH` is used. `gatecheck semgrep` also accepts `osemgrep` on `PATH`. `gatecheck osemgrep` looks only for `osemgrep`.

`semgrep` and `osemgrep` run the osemgrep binary from the semgrep wheel. For `scan`, `--experimental` is added when you omitted it and the program that will run is named `osemgrep`. Other osemgrep commands need you to pass `--experimental`. `gatecheck semgrep --experimental --version` prints the osemgrep version.

If no binary is found, the command prints `gatecheck: <name> is not installed; run `gatecheck bootstrap`` and exits 2.

## gatecheck agent-guide

```
gatecheck agent-guide
```

Alias: `llm`.

Prints a markdown guide for agents that run the CLI. The text is `docs/agent-guide.md`.

```shell
gatecheck agent-guide
gatecheck llm
```

## gatecheck update

```
gatecheck update
```

Aliases: `self-update`, `upgrade`.

Replaces the running gatecheck binary with a release from <https://github.com/gatecheckdev/gatecheck/releases>. The running version is `main.cliVersion`, which goreleaser sets with ldflags. The default is the latest release.

Release archives are named `gatecheck_<version>_<os>_<arch>.tar.gz` for darwin, linux, and windows. The version in the name has no leading `v`. Windows archives are `tar.gz`, the same as the other operating systems. gatecheck downloads `checksums.txt` and checks the SHA256 before it replaces the binary. A missing or different checksum stops the update.

The new file is written next to the resolved executable (`os.Executable`, then `filepath.EvalSymlinks`) and renamed into place. On Windows the running executable is renamed aside first, because a running `.exe` cannot be overwritten. If that directory is not writable, the command stops and tells you to re-run with sudo or to reinstall into a directory you can write.

A build whose version is unset, `dev`, `[Not Provided]`, or otherwise not a release version does not update unless `--version` is set.

- `--check`: print the current version and the latest release, then exit 0. The archive is not downloaded.
- `--version vX.Y.Z`: install that release instead of the latest. With `--check`, print that release as the target and do not download.
- `-y`, `--yes`: do not ask for confirmation.

When stdin is a terminal and `--yes` is not set, gatecheck asks before replacing the binary. When stdin is not a terminal, the update runs only with `--yes`.

`GITHUB_TOKEN`, when set, is sent on the GitHub requests. The client uses the default transport, so the proxy environment variables apply. Requests use the same gatecheck User-Agent as EPSS downloads. No other command contacts GitHub for updates.

```shell
gatecheck update --check
gatecheck update
gatecheck update --version v0.8.1 --yes
```

## gatecheck completion

```
gatecheck completion bash
gatecheck completion fish
gatecheck completion powershell
gatecheck completion zsh
```

Prints a completion script for that shell.

## gatecheck help

```
gatecheck help [command]
```

Prints help for a command. `gatecheck validate --help` does the same.

## Environment variables

| Variable | Commands | Same as |
| --- | --- | --- |
| `GATECHECK_CONFIG_FILENAME` | `validate` | `--config` |
| `GATECHECK_AUDIT` | `validate` | `--audit` |
| `GATECHECK_VEX` | `validate` | `--vex`, comma-separated |
| `GATECHECK_EPSS_FILENAME` | `list`, `list-all`, `validate` | `--epss-filename` |
| `GATECHECK_EPSS_URL` | `download epss`, `list`, `list-all`, `validate` | `--epss-url` |
| `GATECHECK_EPSS_CACHE_DIR` | `download epss`, `list`, `list-all`, `validate` | `--epss-cache-dir` |
| `GATECHECK_EPSS_CACHE` | `download epss`, `list`, `list-all`, `validate` | `--epss-no-cache` when the value is `off` |
| `GATECHECK_KEV_FILENAME` | `validate` | `--kev-filename` |
| `GATECHECK_KEV_URL` | `download kev`, `validate` | `--kev-url` |
| `GATECHECK_BUNDLE_TAG` | `bundle create`, `bundle add` | `--tag`, as a comma-separated list |
| `GATECHECK_VERBOSE` | every command | `--verbose` |
| `GATECHECK_SILENT` | every command | `--silent` |
| `GATECHECK_LOG_LEVEL` | every command | `--log-level` |
| `GATECHECK_LOG_FORMAT` | every command | `--log-format` |
| `GATECHECK_HOME` | `bootstrap`, `grype`, `syft`, `gitleaks`, `semgrep`, `osemgrep`, `trivy`, `osv-scanner`, `gosec`, `hadolint`, `zizmor` | data directory; binaries are in `bin` under it |

A flag on the command line wins over its variable. An empty variable counts as unset. `GATECHECK_AUDIT`, `GATECHECK_VERBOSE`, and `GATECHECK_SILENT` take `true`, `false`, `1`, `0`, `t`, or `f`, and any other value exits 2. `GATECHECK_EPSS_CACHE` also disables the cache for `0`, `false`, `no`, `disabled`, `disable`, and `none`.

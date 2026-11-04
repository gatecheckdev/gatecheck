# gatecheck

Gatecheck reads a scanner report, compares it to thresholds in a config file, and exits non-zero when a threshold fails. It also prints a table of a report, packs reports into one bundle, and downloads EPSS and KEV data. `gatecheck bootstrap` installs Grype, Syft, Gitleaks, semgrep's experimental osemgrep CLI, Trivy, and osv-scanner, plus gosec, hadolint, and zizmor on request, and the matching subcommands run them. Coverage reports still come from the language toolchain.

`gatecheck` with no arguments prints nothing and exits 0. `gatecheck --help` lists commands. `gatecheck agent-guide` (alias `llm`) prints this file.

Logs go to stderr. Tables, `config init`, downloads, and this guide go to stdout.

## Commands

- `version`, and `--version` on the root command only, prints build info. A build that did not set those values prints `[Not Provided]`.
- `config init` writes a default config to stdout. `config convert` rewrites a config into another format.
- `list` (aliases `ls`, `print`) prints one report. `list-all` prints several files.
- `validate` compares one report, or one bundle, to a config.
- `bundle create` (alias `init`), `bundle add`, and `bundle remove` (alias `rm`) manage a bundle.
- `download epss` and `download kev` write upstream data to stdout.
- `bootstrap` installs Grype, Syft, Gitleaks, osemgrep, Trivy, and osv-scanner. `--tools gosec,hadolint,zizmor` installs those too. `grype`, `syft`, `gitleaks`, `semgrep`, `osemgrep`, `trivy`, `osv-scanner`, `gosec`, `hadolint`, and `zizmor` run those binaries.
- `update` (aliases `self-update`, `upgrade`) replaces this binary with a GitHub release after checking `checksums.txt`. `update --check` only prints the current and latest versions.
- `completion bash|fish|powershell|zsh` prints a shell completion script.
- `help [command]` prints the same text as `<command> --help`.

Global flags, on every command: `-v` / `--verbose` (debug logs), `--silent` (warnings and errors), `--log-level debug|info|warn|error` (default `info`), and `--log-format text|json` (default `text`). Only one of `--verbose`, `--silent`, and `--log-level` can be set. `-h` / `--help` is also global. The scanner commands pass every argument through, including `--help`, so `gatecheck grype --help` is Grype's help.

## Scanners

`gatecheck bootstrap` downloads pinned releases into the gatecheck data directory and checks each file's SHA-256. Grype, Syft, and Gitleaks come from their GitHub release assets and checksum files. Semgrep publishes no GitHub release assets. Bootstrap downloads the PyPI wheel for this platform, checks the digest in the PyPI JSON, and installs the wheel's native `semgrep-core` binary as `osemgrep`. That binary is semgrep's experimental native CLI. On Linux the wheel's `libs` directory is installed beside it. On Windows the file is `osemgrep.exe`.

Trivy comes from the `aquasecurity/trivy` GitHub release. The asset names look like `trivy_0.76.1_Linux-64bit.tar.gz`, `trivy_0.76.1_macOS-ARM64.tar.gz`, and `trivy_0.76.1_windows-64bit.zip`. The checksum file is `trivy_<version>_checksums.txt`. Linux arm is the armv7 archive. Windows arm64 has no published asset.

osv-scanner comes from the `google/osv-scanner` GitHub release as a raw binary, not an archive. Asset names look like `osv-scanner_linux_amd64`, `osv-scanner_darwin_arm64`, and `osv-scanner_windows_amd64.exe`. The checksum file is `osv-scanner_SHA256SUMS`. Published builds are amd64 and arm64 on Linux, macOS, and Windows. The installed name is `osv-scanner`, or `osv-scanner.exe` on Windows.

gosec, hadolint, and zizmor are installed only when named in `--tools`. gosec comes from `securego/gosec` as `gosec_<version>_<os>_<arch>.tar.gz` (tar.gz on Windows too), checked against `gosec_<version>_checksums.txt`. hadolint comes from `hadolint/hadolint` as a raw binary such as `hadolint-linux-x86_64` or `hadolint-macos-arm64`, checked against `checksums.sha256`. zizmor comes from `zizmorcore/zizmor` as `zizmor-<arch>-<target>.tar.gz` (`.zip` on Windows). zizmor publishes no checksum file, so its digests are pinned in `internal/bootstrap/versions.go`. hadolint and zizmor have no Windows arm64 build. All three write SARIF, which `list` and `validate` read with the `sarif` config section.

The directory is `$GATECHECK_HOME/bin` when `GATECHECK_HOME` is set. Otherwise it is `$XDG_DATA_HOME/gatecheck/bin`, or `~/.local/share/gatecheck/bin` on Linux, `~/Library/Application Support/gatecheck/bin` on macOS, and `%LOCALAPPDATA%\gatecheck\bin` on Windows.

A tool already at the pinned version is left in place. `--force` downloads it again. `--tools grype,syft` limits the set. `osemgrep` in `--tools` means semgrep. `--list` prints pinned versions, installed versions, and paths, and does not download.

```shell
gatecheck bootstrap
gatecheck bootstrap --list
gatecheck grype dir:latest -o json > grype-report.json
gatecheck semgrep scan --json --config auto .
gatecheck trivy fs --format json --output trivy-report.json .
gatecheck osv-scanner scan source --format json . > osv-scanner-report.json
gatecheck bootstrap --tools gosec,hadolint,zizmor
gatecheck gosec -fmt sarif -out gosec.sarif ./...
gatecheck hadolint -f sarif Dockerfile > hadolint.sarif
gatecheck zizmor --format sarif .github/workflows > zizmor.sarif
```

`gatecheck semgrep scan` and `gatecheck osemgrep scan` insert `--experimental` after `scan` when that flag is absent. Other osemgrep commands need `--experimental` from the caller. `gatecheck semgrep --experimental --version` prints the osemgrep version. When the program that runs is the Python `semgrep` on `PATH`, the flag is left alone. `gatecheck osemgrep` looks for the managed binary, then `osemgrep` on `PATH`.

The managed binary wins when it is present. `gatecheck grype`, `gatecheck syft`, `gatecheck gitleaks`, `gatecheck trivy`, `gatecheck osv-scanner`, `gatecheck gosec`, `gatecheck hadolint`, and `gatecheck zizmor` otherwise run that name on `PATH`. `gatecheck semgrep` tries `semgrep` and then `osemgrep` on `PATH`. If none exist, the command prints `gatecheck: <name> is not installed; run `gatecheck bootstrap`` and exits 2. A scanner's own exit status is returned as-is.

A platform with no release asset for a requested GitHub-hosted tool fails that tool and the command exits 2. A platform with no semgrep wheel prints a skip message on stderr and continues. Current pins are Grype `0.121.0`, Syft `1.55.0`, Gitleaks `8.30.1`, semgrep `1.182.1`, Trivy `0.76.1`, osv-scanner `2.7.0`, gosec `2.30.0`, hadolint `2.15.1`, and zizmor `1.32.0`, in `internal/bootstrap/versions.go`.

Syft is installed so it can write CycloneDX (`syft -o cyclonedx-json`). That BOM is listed and validated as CycloneDX. Native Syft JSON is recognized from `descriptor.name` or the schema URL. `list` prints its packages and licenses, and `validate` runs the license rules on it. CycloneDX is a report format, and coverage tools are left to the language toolchain.

## Report type

`list` and `validate` pick a type from the file contents. The filename is used only when the contents do not identify a type.

Content rules, in this order:

1. A gzipped tar that contains `gatecheck-manifest.json` is a Gatecheck bundle.
2. `bomFormat` of `CycloneDX` is CycloneDX JSON. This wins when the name contains `grype` or `syft`, and it wins when the tool that wrote the BOM was Grype, Syft, Trivy, or another tool. CycloneDX XML is not read.
3. SARIF 2.1.0. The top-level `version` is the string `2.1.0` and `runs` is an array. A `$schema` that mentions SARIF is enough when `runs` is missing or null. Another version returns an error when the name says `sarif`.
4. Grype JSON. `descriptor.name` is `grype`, or `matches` is a non-empty array of objects with `vulnerability` and `artifact`.
5. Syft JSON. `descriptor.name` is `syft`, or `schema.url` points at the Syft schema. `list` prints packages and licenses, and `validate` runs the license rules. A Syft CycloneDX BOM is CycloneDX, not Syft.
6. Semgrep JSON. `results` is an array of objects with `check_id`, or `results` and `errors` are both arrays. Semgrep's SARIF output is SARIF, not this type.
7. Gitleaks JSON. A non-empty array of objects with `RuleID` and one of `File`, `Commit`, or `Fingerprint`.
8. Trivy JSON. `SchemaVersion` is a number, and `ArtifactType` is set or `Results` is an array. Vulnerability entries are listed and validated. Misconfigurations, secrets, and licenses are ignored. A CycloneDX BOM from Trivy is CycloneDX.
9. osv-scanner JSON. `results` is a non-empty array of objects with a `packages` array. One finding per vulnerability group. Aliases of that group are not counted again. License-only packages are skipped. Semgrep is checked first, so a `check_id` stays Semgrep. `{"results":[]}` does not identify itself.
10. LCOV text. A line starts with `SF:` and the file also has `DA:`, `LF:`, or `end_of_record`.
11. Clover XML. An XML document with `clover=` or a `<clover` element.
12. Cobertura XML. An XML document with `line-rate=`.

When none of those match, the filename is checked. The match is a lowercase substring, and the first match wins:

1. `grype`: Anchore Grype JSON.
2. `cyclonedx`: CycloneDX JSON that includes vulnerabilities.
3. `semgrep`: Semgrep JSON.
4. `gitleaks`: Gitleaks JSON, a list of findings.
5. `trivy`: Trivy JSON. On an ambiguous file, `cyclonedx` is earlier, so `cyclonedx-trivy-sbom.json` is CycloneDX.
6. `osv`: osv-scanner JSON. `osv-scanner-report.json` matches. `OSV-scanner.json` does not.
7. `syft`: the name is recognized. `list` and `validate` then return an error.
8. `sarif`: SARIF 2.1.0.
9. `bundle`: a Gatecheck bundle. `list` also accepts a name containing `gatecheck`. `validate` requires the word `bundle` for this fallback. A real bundle is still detected from its contents when the name is `project.gcb`.
10. Coverage, when the name contains `lcov`, `clover`, `cobertura`, or `coverage`, or ends in `.info`.

The filename match is case sensitive. `Grype-report.json` is not a filename match. A Grype report is still recognized from its contents when `descriptor.name` is `grype`. An earlier word still wins on an ambiguous file, so `semgrep-coverage.json` is Semgrep when the contents do not say otherwise.

An empty Grype document such as `{"matches":[]}` does not identify itself. The filename is what selects it. The same is true of `{"results":[]}` and `[]`.

Coverage format when the name is the only signal, in this order: the name contains `lcov` or ends in `.info` (LCOV); the name contains `clover` (Clover XML); the name ends in `.xml` (Cobertura XML). A name that only contains `coverage`, such as `coverage.json`, is selected as coverage and then fails.

From standard input, `list` requires `-i` / `--input-type`, so the command does not wait on a terminal. The value is matched as the filename `stdin:<value>`, and only when the contents are ambiguous. Clear contents win over `--input-type`. `list-all` and `validate` do not read standard input. `validate` requires a file path.

`list-all` lists a file when the contents or the name identify Grype, Semgrep, Gitleaks, Syft, CycloneDX, SARIF, Trivy, osv-scanner, or a bundle. Coverage files are skipped with a warning. There is no `--input-type` on `list-all`.

Inside a bundle, `validate` uses the same content rules on each stored file, and falls back to the label. The label is the base name of the file that was added. Labels that still do not match are skipped. Syft JSON inside a bundle is checked with the license rules.

## Config

```shell
gatecheck config init > gatecheck.yaml
gatecheck config init --output json > gatecheck.json
gatecheck config convert --file gatecheck.yaml --output toml
```

`-o` / `--output` accepts `json`, `.json`, `toml`, `.toml`, `yaml`, `yml`, `.yaml`, or `.yml`. The default is `yaml`. Any other value is an error. The match is case sensitive.

`config convert` reads `-f` / `--file` (default `gatecheck.yaml`). The extension selects the decoder: `.yaml`, `.yml`, `.json`, or `.toml`.

A partial file is fine. Omitted fields keep the default. Unknown keys, such as a misspelled `severityLimt`, are named in a warning on stderr, and the rest of the file is still used. With no config, `validate` uses the built-in default: every rule disabled, coverage thresholds `0`. Grype, CycloneDX, Trivy, osv-scanner, SARIF, Semgrep, Gitleaks, coverage, and bundle reports pass under that default. Syft JSON passes too, since the license rules are off by default. An old config with no `sarif` section leaves those limits disabled.

`GATECHECK_CONFIG_FILENAME` is the same setting as `validate --config` / `-f`.

Field names below are the ones `config init` emits. In YAML they are case sensitive. `version` (currently `"1"`) and `metadata.tags` do not change validation.

`grype`, `cyclonedx`, `trivy`, and `osv-scanner` use the same fields. The config key is `osv-scanner`.

- `severityLimit` has `critical`, `high`, `medium`, and `low`. Each has `enabled` and `limit`. `limit` is a count. The report fails when the count is greater than `limit`. A count equal to `limit` passes. `enabled: true` and `limit: 0` allows none. `enabled: false` skips that severity. `negligible` and `unknown` have no limit field.
- `epssLimit.score` and `epssRiskAcceptance.score` are EPSS ratios from 0 to 1, the same scale as the FIRST CSV. The limit fails when a CVE's score is greater than `score`. A score equal to the limit passes. A CVE with no EPSS row passes the limit. Risk acceptance removes a CVE when `score` is greater than that CVE's score. An equal score is kept. A CVE with no EPSS row is kept.
- `kevLimitEnabled` fails the report when any remaining CVE is in the CISA catalog.
- `cveLimit` and `cveRiskAcceptance` each have `enabled` and `cves`. A CVE entry is `id` plus an optional `metadata.tags` list. `id` is compared without regard to case. Trivy matches `VulnerabilityID` and each `VendorIDs` entry, so a GHSA primary id still matches a CVE in `VendorIDs`. osv-scanner matches the OSV id and each alias. EPSS and KEV use the first id that starts with `CVE-`.
- osv-scanner `max_severity` is a CVSS base score: `9.0` and above is critical, `7.0` high, `4.0` medium, `0.1` low, and anything lower is unknown. The words `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `MODERATE`, and `UNKNOWN` are accepted. `MODERATE` is medium. A CVSS vector with no numeric score is unknown. `database_specific.severity` is used when `max_severity` is empty.

`semgrep.severityLimit` has `error`, `warning`, and `info`, each with `enabled` and `limit`, with the same count rule. `impactRiskAcceptance` has `enabled`, `high`, `medium`, and `low`. When `enabled` is true, a finding is removed when its impact matches a level whose value is true.

`gitleaks.limitEnabled: true` fails validation when the report contains any finding. There is no count.

`sarif` is for any SARIF 2.1.0 report. Semgrep's own JSON still uses `semgrep`. `semgrep --sarif` uses `sarif`.

- `severityLimit` has `critical`, `high`, `medium`, and `low`. Each has `enabled` and `limit`, with the same count rule as Grype. The severity comes from the SARIF property `security-severity` when a result or its rule has one. The value is a number from 0 to 10, or a numeric string. 9.0 and above is critical, 7.0 to 8.9 is high, 4.0 to 6.9 is medium, above 0 and below 4.0 is low, and 0 is none. A result property wins over the same property on the rule. When neither is set, gatecheck uses the SARIF level. A missing result level uses the rule's `defaultConfiguration.level`, then `warning`. `error` is high, `warning` is medium, `note` is low, and `none` is ignored.
- `ruleLimit` and `ruleRiskAcceptance` each have `enabled` and `rules`. A rule entry is `id` plus an optional `metadata.tags` list. `id` is compared without regard to case. `ruleLimit` denies those ids. `ruleRiskAcceptance` removes them.

`license` gates package licenses in Syft JSON and CycloneDX BOMs. `enabled` turns it on. `deny` and `allow` are case-insensitive glob patterns such as `GPL-*`, which matches `GPL-3.0-only` but not `LGPL-2.1-only`. A non-empty `allow` fails every license outside it. `denyUnknown` fails packages with no license, `NOASSERTION`, or `NONE`. `packageRiskAcceptance` entries skip a package by `purl` (type, namespace, and name, plus version when given) or by `name`. SPDX expressions are evaluated: `OR` passes when either side passes, `AND` needs both, and `X WITH Y` is denied when `X` is denied unless `allow` names the full `X WITH Y`. Several license entries on one package must all pass. Syft licenses are `spdxExpression`, then `value`. CycloneDX licenses are `expression`, `license.id`, then `license.name`, and nested components are included. A CycloneDX BOM runs both the license and vulnerability rules, and reports both failures.

`vex.files` lists OpenVEX or CycloneDX VEX documents, read along with `--vex`.

`coverage.lineThreshold`, `functionThreshold`, and `branchThreshold` are ratios from 0 to 1: covered lines, functions, or branches divided by the total. The report fails when its ratio is less than the threshold. A ratio equal to the threshold passes. `0.8` is 80 percent. A threshold over 1 is read as a percent, so `80` means `0.8`, and a warning says so. There is no `enabled` flag. The default `0` allows any coverage, because a ratio is never less than 0. `list` prints these numbers as percents in the table footer. The config still wants the ratio. A report with no records of a kind, such as LCOV without branch records, has no ratio for it. `list` prints `N/A`, and `validate` skips that threshold with a warning.

Grype, CycloneDX, Trivy, and osv-scanner rules run in this order. A failure returns immediately, except where a rule only removes findings. Trivy counts vulnerability entries only. osv-scanner counts one finding per group.

1. CVE limit, when enabled.
2. Disabled Grype, Trivy, and osv-scanner severities are dropped. If the EPSS limit is also enabled, a finding at a disabled severity stays when its EPSS score is greater than or equal to that limit. CycloneDX leaves findings at a disabled severity in the report.
3. CVE risk acceptance removes matching ids. VEX statements that mark a finding not exploitable remove it here too.
4. KEV limit, when `kevLimitEnabled` is true.
5. EPSS risk acceptance.
6. EPSS limit.
7. Severity limit.

Semgrep drops findings whose severity limit is disabled, then applies impact risk acceptance, then the severity counts. That impact rule does not apply to `semgrep --sarif`. That file uses the `sarif` rules.

SARIF runs in this order.

1. Rule limit, when enabled. A denied rule fails even when its severity limit is disabled.
2. Disabled severities are dropped. `none` has no limit field and stays in the report, but the severity rule does not count it.
3. Rule risk acceptance removes matching ids.
4. Severity limit.

These SARIF results are not counted: `kind` of `pass` or `notApplicable`, `level` of `none`, a non-empty `suppressions` array, and `baselineState` of `absent`. SARIF has no EPSS or KEV rules.

Any CycloneDX JSON BOM uses the `cyclonedx` rules, including a BOM from Grype, Trivy, Syft, or another tool. The severity is the highest rating. A rating with a score and no severity word uses CVSS ranges. A CVSS v2 method does not produce critical. `important` counts as high, and `moderate` counts as medium. `negligible` counts as none. Empty ratings use a top-level `severity` string when the producer set one, otherwise `unknown`. `unknown`, `none`, and `info` are not counted by the critical, high, medium, or low limits. The id is the vulnerability `id`, or the `bom-ref` when `id` is empty.

Coverage runs all three checks and reports each failure. A bundle is validated when its contents are a Gatecheck bundle, or when the filename contains `bundle` and the contents do not identify another type. Each stored file is checked on its own. The command exits 1 if any file fails a threshold.

## validate

```shell
gatecheck validate --config gatecheck.yaml grype-report.json
gatecheck validate --audit --config gatecheck.yaml gatecheck-bundle.tar.gz
```

The report path is the positional argument. With no path, `--input-type` is required and the report is read from stdin. Pass the config with `--config` or `-f`. With no config, a warning says every rule is disabled.

Exit status, for `validate` and every other gatecheck command:

- `0`: success. With `--audit` / `-a`, a threshold failure is printed to stderr and the process still exits 0.
- `1`: a threshold failed and `--audit` is off. The error text starts with `validation failure:`.
- `2`: usage error, a file that could not be opened or written, or a report, config, or VEX file that could not be decoded. `--audit` does not change this.
- `3`: EPSS or KEV data could not be downloaded or read. `--audit` does not change this.

`--format table|markdown|json` also prints the result to stdout. JSON is `{"report": "...", "passed": false, "failures": ["Grype: Severity Limit Exceeded"]}`, plus `"error"` when the check stopped on something else. Without `--format`, stdout is empty.

`--epss-filename` is the EPSS CSV used when an EPSS rule is enabled. `--kev-filename` is the CISA KEV JSON used when `kevLimitEnabled` is true. `--epss-url` and `--kev-url` change the feeds. `--epss-cache-dir` and `--epss-no-cache` apply when that CSV is downloaded.

`--vex FILE` (repeatable), `GATECHECK_VEX` (comma-separated, used when the flag is absent), and the config's `vex.files` name OpenVEX or CycloneDX VEX documents. Grype, CycloneDX, Trivy, and osv-scanner findings that a VEX file marks `not_affected` or `fixed` (OpenVEX), or `not_affected`, `false_positive`, `resolved`, or `resolved_with_pedigree` (CycloneDX `analysis.state`), are removed right after the `cveLimit` deny list, so they skip the KEV, EPSS, and severity rules. Ids match the finding's id or aliases. A statement that lists subcomponents or `affects` refs matches only those package URLs. The OpenVEX product itself is not checked. When several statements match, the latest timestamp wins.

EPSS data is loaded only when an EPSS limit or EPSS risk acceptance rule is enabled. KEV data is loaded only when `kevLimitEnabled` is true for Grype, CycloneDX, Trivy, or osv-scanner. With no local EPSS file, gatecheck downloads the current CSV and caches it until the published date changes.

## list

```shell
gatecheck list grype-report.json
gatecheck list --format markdown --epss grype-report.json
gatecheck list --format json trivy-report.json
grype image:tag -o json | gatecheck ls --input-type grype
gatecheck list-all grype-report.json semgrep-report.json
```

`list` takes one filename, or stdin with `--input-type`. `--format table|markdown|json` picks the output, and `--markdown` is the same as `--format markdown`. JSON is `{"columns": [...], "rows": [{column: value}], "footer": {...}}`. A Grype, CycloneDX, SARIF, Semgrep, Gitleaks, Trivy, osv-scanner, or Syft report with nothing in it prints one sentence and no table: `No grype vulnerabilities`, `No cyclonedx vulnerabilities`, `No sarif findings`, `No semgrep findings`, `No gitleaks findings`, `No trivy vulnerabilities`, `No osv-scanner vulnerabilities`, or `No syft packages`. In JSON that is `{"columns": [], "rows": [], "message": "..."}`. Syft JSON lists package, version, type, and licenses. `--epss` adds EPSS score and percentile columns for Grype, CycloneDX, Trivy, and osv-scanner. Other report types still list, and those columns are omitted. `--epss-url` empty uses `https://epss.cyentia.com`. `--epss-filename` reads that CSV instead of calling the API.

`list-all` prints each filename, then its table, or that sentence when the report has nothing in it. With `--format json` it prints one array of `{"file": ..., "report": ...}`. A file whose contents and name are not a supported `list-all` type is skipped with a warning. A file that cannot be read or listed is logged, the rest are still listed, and the command then exits 2. `--epss` adds EPSS data for Grype, CycloneDX, Trivy, and osv-scanner, loaded once per run. `--epss-filename`, `--epss-url`, `--epss-cache-dir`, and `--epss-no-cache` work as on `list`.

## bundle

A bundle is a gzipped tar plus a JSON manifest named `gatecheck-manifest.json`. `list` and `validate` treat the file as a bundle when the contents are that archive. The filename is the fallback: `validate` requires the word `bundle`, and `list` also accepts a name containing `gatecheck`. A name such as `project.gcb` still works when the file is a real bundle. A name that contains `bundle`, such as `gatecheck-bundle.tar.gz`, still works when the contents are ambiguous.

```shell
gatecheck bundle create gatecheck-bundle.tar.gz grype-report.json --tag ci
gatecheck bundle add gatecheck-bundle.tar.gz semgrep-report.json
gatecheck bundle remove gatecheck-bundle.tar.gz semgrep-report.json
gatecheck list gatecheck-bundle.tar.gz
```

The stored label is the base name of the target file (`reports/grype-report.json` is stored as `grype-report.json`). Later validation uses the file contents to pick the type, and the label when the contents are ambiguous. Repeat `-t` / `--tag` for more than one tag. When the flag is omitted, `GATECHECK_BUNDLE_TAG` is read as a comma-separated list. `bundle create` replaces an existing file. `bundle add` requires an existing bundle. `bundle remove` takes the label, not a path that is opened. A label that is not in the bundle exits 2 and leaves the bundle unchanged. There is no `bundle list` subcommand. `gatecheck list` prints label, SHA-256 digest, tags, and size.

## download

```shell
gatecheck download epss > epss.csv
gatecheck download kev > kev.json
```

`download epss` writes the FIRST.org EPSS CSV to stdout. An empty `--epss-url` uses `https://epss.cyentia.com`. Files are cached in the user cache directory under `gatecheck/epss`. gatecheck follows the redirect to the dated filename and downloads only when that date is not already cached. `--epss-cache-dir` changes the directory. `--epss-no-cache` downloads on every run.

`download kev` writes the CISA Known Exploited Vulnerabilities catalog as JSON to stdout. An empty `--kev-url` uses `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.

EPSS requests send a User-Agent with the gatecheck version and `https://github.com/gatecheckdev/gatecheck`.

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

## Minimal CI

```yaml
- name: Validate Grype report
  run: gatecheck validate --config gatecheck.yaml grype-report.json
```

Create the config with `gatecheck config init > gatecheck.yaml` and set real thresholds before relying on it. The generated file leaves every rule disabled, so this step passes until the file is edited. The process exit status is the gate result. Do not wrap the command in a way that ignores exit code 1.

## Common mistakes

- The contents do not identify a type and the filename has no lowercase type word (`scan.json`, `Grype.json`). A real bundle named `project.gcb` is still recognized from its contents. An empty document such as `{"matches":[]}` still needs a name such as `grype-report.json`, or `--input-type grype` on standard input.
- Coverage thresholds are ratios. Set `coverage.lineThreshold` to `0.8` for 80 percent. A value over 1, such as `80`, is read as a percent with a warning.
- `validate` takes the report as its positional argument. The config is `--config` / `-f`. `gatecheck validate gatecheck.yaml grype-report.json` tries to open the config as a report. `config convert` uses `--file` / `-f`, which is a different flag.
- `list` and `validate` on a pipe need `--input-type`. Clear contents still win over that flag.
- `list` takes one filename, and a second one exits 2. Use `list-all` for several files. `list-all` skips coverage files such as `lcov.info`. List those with `gatecheck list lcov.info`.
- Native Syft JSON gets only the license rules. Use CycloneDX output when you also want vulnerabilities scored. That BOM is CycloneDX even when the filename contains `syft`.
- `gatecheck semgrep --version` reaches osemgrep without `--experimental`, and osemgrep then tries to run `pysemgrep`. Pass the flag: `gatecheck semgrep --experimental --version`.
- `--audit` only hides threshold failures. It still exits 2 when the report, the config, or a named EPSS, KEV, or VEX file cannot be opened, and 3 when EPSS or KEV data cannot be loaded.

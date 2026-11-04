# Validation

```shell
gatecheck validate --config gatecheck.yaml grype-report.json
gatecheck validate --config gatecheck.yaml gatecheck-bundle.tar.gz
```

Pass the config with `--config` or `-f`, or with `GATECHECK_CONFIG_FILENAME`. The positional argument is the report path. With no path, `--input-type` names the report type and the report is read from standard input:

```shell
grype dir:. -o json | gatecheck validate --config gatecheck.yaml --input-type grype
```

`--format table`, `markdown`, or `json` also prints the result to standard output. Keys in the config that gatecheck does not read are named in a warning, so a typo such as `severityLimt` does not silently disable a rule.

The report type comes from the file contents, and from the filename when the contents are ambiguous. See [Supported Reports](./supported-reports.md).

With no config, gatecheck warns and uses the default: every rule disabled, coverage thresholds `0`. Grype, CycloneDX, Trivy, osv-scanner, SARIF, Semgrep, Gitleaks, coverage, and bundle reports pass under that default. Syft JSON passes too, since the license rules are off by default. An old config with no `sarif` section leaves those limits disabled.

## Exit status

- `0`: the report passed.
- `1`: a threshold failed. The error text starts with `validation failure:`.
- `2`: the report, config, VEX, EPSS, or KEV file could not be opened or decoded, the report type is not supported, the config extension is not supported, or the command line was rejected.
- `3`: EPSS or KEV data could not be downloaded or read.

`--audit` (`-a`) prints a threshold failure and exits 0. It does not hide anything else: those errors still exit 2 or 3. `GATECHECK_AUDIT=true` is the same setting, and `--audit=false` overrides it.

## Grype, CycloneDX, Trivy, and osv-scanner

Trivy uses these same rules. It counts vulnerability entries from `Results[].Vulnerabilities`. Misconfigurations, secrets, and licenses are not scored. An id matches `VulnerabilityID` or a `VendorIDs` entry, without regard to case. EPSS and KEV look up the first id that starts with `CVE-`.

osv-scanner uses these same rules. It counts one finding per vulnerability group, so aliases are not double-counted. License-only packages are skipped. `max_severity` is a CVSS base score (`9.8` is critical, `7.5` is high, `4.0` is medium, `0.1` is low). The words `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `MODERATE`, and `UNKNOWN` are accepted, and `MODERATE` maps to medium. A CVSS vector with no numeric score is unknown unless `database_specific.severity` supplies a rating. Deny, allow, and KEV match the OSV id or any alias. EPSS and KEV look up the first id that starts with `CVE-`.

Rules run in this order. A failure returns immediately, except where a rule only removes findings.

1. **CVE limit.** `cveLimit`, when enabled, fails if any listed id is in the report. Ids are compared without regard to case.
2. **Disabled Grype, Trivy, and osv-scanner severities.** Grype, Trivy, and osv-scanner drop findings whose severity limit is disabled. If the EPSS limit is also enabled, a finding at a disabled severity stays in the report when it has an EPSS score greater than or equal to that limit. CycloneDX leaves findings at a disabled severity in the report, so they still go through the KEV and EPSS rules.
3. **CVE risk acceptance and VEX.** Matching ids are removed and skip the remaining rules. Findings that a VEX file passed with `--vex`, `GATECHECK_VEX`, or `vex.files` marks `not_affected`, `fixed`, `false_positive`, or `resolved` are removed too. See [VEX](./vex.md).
4. **KEV limit.** When `kevLimitEnabled` is true, a CVE that is in the catalog fails the report. The catalog is `--kev-filename` (`GATECHECK_KEV_FILENAME`) or, with no file, the CISA feed. `--kev-url` (`GATECHECK_KEV_URL`) changes the feed. Grype ids are compared without regard to case, and a Grype match's related CVE ids are checked too.
5. **EPSS risk acceptance.** A CVE is removed when the configured `score` is greater than that CVE's EPSS score. A CVE with no EPSS row is kept. A CVE whose score is equal to the configured score is kept.
6. **EPSS limit.** A CVE fails when its EPSS score is greater than `score`. A CVE with no EPSS row passes this rule. A score equal to the limit passes. Data comes from `--epss-filename` or `GATECHECK_EPSS_FILENAME`, or from the API. `--epss-url` (`GATECHECK_EPSS_URL`) changes the API.
7. **Severity limit.** For each enabled severity, the report fails when the count is greater than `limit`. `limit: 0` allows none. Counts that are equal to the limit pass. Grype, CycloneDX, Trivy, and osv-scanner severities are `critical`, `high`, `medium`, and `low`. `negligible` and `unknown` have no limit field.

Any CycloneDX JSON BOM uses the `cyclonedx` rules, including a BOM from Grype, Trivy, Syft, or another tool. The severity is the highest rating. A rating with a score and no severity word uses CVSS ranges. A CVSS v2 method does not produce critical. `important` counts as high, and `moderate` counts as medium. `negligible` counts as none. Empty ratings use a top-level `severity` string when the producer set one, otherwise `unknown`. `unknown`, `none`, and `info` are not counted by the critical, high, medium, or low limits. The id is the vulnerability `id`, or the `bom-ref` when `id` is empty.

EPSS scores in the config are ratios from 0 to 1.

When a rule needs EPSS scores and `--epss-filename` is not set, gatecheck downloads the current EPSS file and caches it until the published date changes. Requests send a User-Agent with the gatecheck version and project URL.

## Licenses

Syft JSON and CycloneDX BOMs are checked against the `license` section of the config: deny patterns, an optional allow list, packages with no license, and per-package risk acceptance. For a CycloneDX BOM the license rules run alongside the vulnerability rules above, and both failures are reported. See [License gating](./licenses.md).

## Semgrep

1. Findings whose severity limit is disabled are dropped.
2. **Impact risk acceptance.** When enabled, a finding is removed when its impact is `high`, `medium`, or `low` and that level's boolean is true. The three booleans are independent.
3. **Severity limit.** Severities are `error`, `warning`, and `info`. The report fails when an enabled severity has more findings than its `limit`.

## SARIF

Rules run in this order. A failure returns immediately, except where a rule only removes findings.

1. **Rule limit.** `ruleLimit`, when enabled, fails if any listed rule id is in the report. Ids are compared without regard to case. This runs before disabled severities are dropped, so a denied rule fails even when its severity limit is disabled.
2. **Disabled severities.** Findings whose severity limit is disabled are dropped. `none` has no limit field and stays in the report, but the severity rule does not count it.
3. **Rule risk acceptance.** Matching rule ids are removed and skip the remaining rules.
4. **Severity limit.** For each enabled severity, the report fails when the count is greater than `limit`. `limit: 0` allows none. Counts that are equal to the limit pass. Severities are `critical`, `high`, `medium`, and `low`.

The severity mapping is in [Configuration](./configuration.md). These results are not counted: `kind` of `pass` or `notApplicable`, `level` of `none`, a non-empty `suppressions` array, and `baselineState` of `absent`.

SARIF has no EPSS or KEV rules. A SARIF version other than 2.1.0 returns an error.

## Gitleaks

When `limitEnabled` is true, any finding in the report fails validation. There is no numeric limit and no separate allow list.

## Coverage

Line, function, and branch coverage are each `covered / total`. The config thresholds are those ratios, from 0 to 1. The check fails when the report's ratio is less than the threshold. A ratio equal to the threshold passes. All three checks run, and each failure is reported. A report with no records of a kind, such as LCOV without branch records, has no ratio for it. `list` prints `N/A`, and `validate` skips that threshold with a warning.

`0.8` means 80 percent. A threshold over 1 is read as a percent, so `80` means `0.8`, and a warning is logged.

`list` prints coverage as a percent. The config value stays a ratio.

## Bundles

A bundle is validated when its contents are a Gatecheck bundle, or when the filename contains `bundle` and the contents do not identify another type. Each stored file is validated with the rules above. The file contents pick the type, and the label is the fallback. Labels that still do not match are skipped. Syft JSON in a bundle is checked with the license rules. Failures are combined, and the command exits 1 if any label fails a threshold.

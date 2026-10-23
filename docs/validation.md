# Validation

```shell
gatecheck validate --config gatecheck.yaml grype-report.json
gatecheck validate --config gatecheck.yaml gatecheck-bundle.tar.gz
```

Pass the config with `--config` or `-f`, or with `GATECHECK_CONFIG_FILENAME`. The only positional argument is the report path, and it is required.

The report type comes from the filename. See [Supported Reports](./supported-reports.md).

With no config, gatecheck uses the default: every rule disabled, coverage thresholds `0`. Grype, CycloneDX, Semgrep, Gitleaks, coverage, and bundle reports pass under that default. A Syft filename still returns an error.

## Exit status

- `0`: the report passed.
- `1`: a threshold failed. The error text starts with `validation failure:`.
- `255`: the report or config could not be opened, the config extension is not supported, or the command line was rejected.

`--audit` (`-a`) prints whatever error the check returns and exits 0. That covers a failed threshold, an unknown filename, a Syft file, a decode error, and a failed EPSS or KEV fetch. Opening the report, the config, and any `--epss-filename` or `--kev-filename` happens before the check. A missing file still exits 255.

## Grype and CycloneDX

Rules run in this order. A failure returns immediately, except where a rule only removes findings.

1. **CVE limit.** `cveLimit`, when enabled, fails if any listed id is in the report. Ids are compared without regard to case.
2. **Disabled Grype severities.** Grype drops findings whose severity limit is disabled. If the EPSS limit is also enabled, a finding at a disabled severity stays in the report when it has an EPSS score greater than or equal to that limit. CycloneDX leaves findings at a disabled severity in the report, so they still go through the KEV and EPSS rules.
3. **CVE risk acceptance.** Matching ids are removed and skip the remaining rules.
4. **KEV limit.** When `kevLimitEnabled` is true, a CVE that is in the catalog fails the report. The catalog is `--kev-filename` or, with no file, the CISA feed. `GATECHECK_KEV_URL` overrides the feed. There is no `--kev-url` flag on `validate`.
5. **EPSS risk acceptance.** A CVE is removed when the configured `score` is greater than that CVE's EPSS score. A CVE with no EPSS row is kept. A CVE whose score is equal to the configured score is kept.
6. **EPSS limit.** A CVE fails when its EPSS score is greater than `score`. A CVE with no EPSS row passes this rule. A score equal to the limit passes. Data comes from `--epss-filename` or `GATECHECK_EPSS_FILENAME`, or from the API. `GATECHECK_EPSS_URL` overrides the API. There is no `--epss-url` flag on `validate`.
7. **Severity limit.** For each enabled severity, the report fails when the count is greater than `limit`. `limit: 0` allows none. Counts that are equal to the limit pass. Grype and CycloneDX severities are `critical`, `high`, `medium`, and `low`. `negligible` and `unknown` have no limit field.

EPSS scores in the config are ratios from 0 to 1.

## Semgrep

1. Findings whose severity limit is disabled are dropped.
2. **Impact risk acceptance.** When enabled, a finding is removed when its impact is `high`, `medium`, or `low` and that level's boolean is true. The three booleans are independent.
3. **Severity limit.** Severities are `error`, `warning`, and `info`. The report fails when an enabled severity has more findings than its `limit`.

## Gitleaks

When `limitEnabled` is true, any finding in the report fails validation. There is no numeric limit and no separate allow list.

## Coverage

Line, function, and branch coverage are each `covered / total`. The config thresholds are those ratios, from 0 to 1. The check fails when the report's ratio is less than the threshold. A ratio equal to the threshold passes. All three checks run, and each failure is reported.

`0.8` means 80 percent. `80.0` fails a normal report, because `0.8 < 80`.

`list` prints coverage as a percent. The config value stays a ratio.

## Bundles

A bundle is validated when the bundle filename contains `bundle`. Each stored label is validated with the rules above. Labels that do not match are skipped. Failures are combined, and the command exits 1 if any label fails a threshold.

# Configuration

`validate` reads YAML, JSON, or TOML. The extension selects the format: `.yaml`, `.yml`, `.json`, or `.toml`.

```shell
gatecheck config init > gatecheck.yaml
```

`config init` writes to standard output. `-o` / `--output` accepts `json`, `.json`, `toml`, `.toml`, `yaml`, `yml`, `.yaml`, and `.yml`. The default is `yaml`.

```shell
gatecheck config convert --file gatecheck.yaml --output json
```

`config convert` reads `--file` / `-f` (default `gatecheck.yaml`) and writes the other format to standard output.

A partial file is fine. Omitted fields keep the default. Keys the decoder does not know are ignored.

`GATECHECK_CONFIG_FILENAME` is the same setting as `validate --config`.

Field names below are the ones `config init` emits. In YAML they are case sensitive. Use the lowercase names.

## Default file

This is what `gatecheck config init` prints.

```yaml
version: "1"
metadata:
    tags: []
grype:
    severityLimit:
        critical:
            enabled: false
            limit: 0
        high:
            enabled: false
            limit: 0
        medium:
            enabled: false
            limit: 0
        low:
            enabled: false
            limit: 0
    epssLimit:
        enabled: false
        score: 0
    kevLimitEnabled: false
    cveLimit:
        enabled: false
        cves: []
    epssRiskAcceptance:
        enabled: false
        score: 0
    cveRiskAcceptance:
        enabled: false
        cves: []
cyclonedx:
    severityLimit:
        critical:
            enabled: false
            limit: 0
        high:
            enabled: false
            limit: 0
        medium:
            enabled: false
            limit: 0
        low:
            enabled: false
            limit: 0
    epssLimit:
        enabled: false
        score: 0
    kevLimitEnabled: false
    cveLimit:
        enabled: false
        cves: []
    epssRiskAcceptance:
        enabled: false
        score: 0
    cveRiskAcceptance:
        enabled: false
        cves: []
trivy:
    severityLimit:
        critical:
            enabled: false
            limit: 0
        high:
            enabled: false
            limit: 0
        medium:
            enabled: false
            limit: 0
        low:
            enabled: false
            limit: 0
    epssLimit:
        enabled: false
        score: 0
    kevLimitEnabled: false
    cveLimit:
        enabled: false
        cves: []
    epssRiskAcceptance:
        enabled: false
        score: 0
    cveRiskAcceptance:
        enabled: false
        cves: []
osv-scanner:
    severityLimit:
        critical:
            enabled: false
            limit: 0
        high:
            enabled: false
            limit: 0
        medium:
            enabled: false
            limit: 0
        low:
            enabled: false
            limit: 0
    epssLimit:
        enabled: false
        score: 0
    kevLimitEnabled: false
    cveLimit:
        enabled: false
        cves: []
    epssRiskAcceptance:
        enabled: false
        score: 0
    cveRiskAcceptance:
        enabled: false
        cves: []
semgrep:
    severityLimit:
        error:
            enabled: false
            limit: 0
        warning:
            enabled: false
            limit: 0
        info:
            enabled: false
            limit: 0
    impactRiskAcceptance:
        enabled: false
        high: false
        medium: false
        low: false
gitleaks:
    limitEnabled: false
coverage:
    lineThreshold: 0
    functionThreshold: 0
    branchThreshold: 0
```

## version and metadata

`version` is the string `"1"`. `metadata.tags` is a list of strings. Neither one changes validation.

## Grype, CycloneDX, Trivy, and osv-scanner

`grype`, `cyclonedx`, `trivy`, and `osv-scanner` use the same fields. Trivy scores vulnerability entries. Misconfigurations, secrets, and licenses in the Trivy JSON are ignored. A Trivy id matches `VulnerabilityID` and each `VendorIDs` entry.

osv-scanner counts one finding per vulnerability group. Aliases of that group are not counted again. License-only packages are skipped. `max_severity` is a CVSS base score: `9.0` and above is critical, `7.0` high, `4.0` medium, `0.1` low, and anything lower is unknown. The words `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `MODERATE`, and `UNKNOWN` are also accepted. `MODERATE` is medium. A CVSS vector with no numeric score is unknown. `database_specific.severity` is used when `max_severity` is empty. Deny, allow, and KEV match the OSV id or any alias. EPSS and KEV look up the first id that starts with `CVE-`.

`severityLimit` has `critical`, `high`, `medium`, and `low`. Each has `enabled` and `limit`. `limit` is a count. The report fails when the number of findings at that severity is greater than `limit`. `enabled: true` and `limit: 0` allows none. `enabled: false` skips that severity.

`epssLimit.score` and `epssRiskAcceptance.score` are EPSS ratios from 0 to 1, the same scale as the FIRST CSV. The limit fails when a CVE's score is greater than `score`. Risk acceptance removes a CVE when `score` is greater than that CVE's score. See [Validation](./validation.md) for the order and the equal-score cases.

`kevLimitEnabled` fails the report when any remaining CVE is in the CISA catalog.

`cveLimit` and `cveRiskAcceptance` each have `enabled` and `cves`. A CVE entry is `id` plus an optional `metadata.tags` list. `id` is compared without regard to case.

```yaml
grype:
  cveLimit:
    enabled: true
    cves:
      - id: CVE-2024-0001
        metadata:
          tags:
            - denied
  cveRiskAcceptance:
    enabled: true
    cves:
      - id: CVE-2023-5678
        metadata:
          tags:
            - accepted
```

## Semgrep

`severityLimit` has `error`, `warning`, and `info`. Each has `enabled` and `limit`, with the same meaning as the Grype counts.

`impactRiskAcceptance` has `enabled`, `high`, `medium`, and `low`. When `enabled` is true, a finding is removed when its impact matches a level whose value is true. `high`, `medium`, and `low` are separate switches.

## Gitleaks

`limitEnabled: true` fails validation when the report contains any finding. `false` skips the check. There is no count.

## Coverage

`lineThreshold`, `functionThreshold`, and `branchThreshold` are ratios from 0 to 1:

- line coverage is covered lines divided by total lines
- function coverage is covered functions divided by total functions
- branch coverage is covered branches divided by total branches

The report fails when its ratio is less than the threshold. `0.8` is 80 percent. `80.0` fails a report whose real line coverage is 0.8, because 0.8 is less than 80.

There is no `enabled` flag. The default `0` allows any coverage, because a ratio is never less than 0.

`gatecheck list` prints these numbers as percents in the table footer. The config still wants the ratio.

## A tighter file

```yaml
version: "1"
metadata:
  tags:
    - ci
grype:
  severityLimit:
    critical:
      enabled: true
      limit: 0
    high:
      enabled: true
      limit: 5
  epssLimit:
    enabled: true
    score: 0.5
  kevLimitEnabled: true
semgrep:
  severityLimit:
    error:
      enabled: true
      limit: 0
    warning:
      enabled: true
      limit: 10
  impactRiskAcceptance:
    enabled: true
    high: false
    medium: true
    low: true
gitleaks:
  limitEnabled: true
coverage:
  lineThreshold: 0.8
  functionThreshold: 0.75
  branchThreshold: 0.7
```

Fields left out of this file keep the defaults from `config init`.

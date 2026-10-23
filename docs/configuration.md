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
sarif:
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
    ruleLimit:
        enabled: false
        rules: []
    ruleRiskAcceptance:
        enabled: false
        rules: []
coverage:
    lineThreshold: 0
    functionThreshold: 0
    branchThreshold: 0
```

## version and metadata

`version` is the string `"1"`. `metadata.tags` is a list of strings. Neither one changes validation.

## Grype and CycloneDX

`grype` and `cyclonedx` use the same fields.

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

## SARIF

`sarif` is for any SARIF 2.1.0 report. Semgrep's own JSON still uses `semgrep`. `semgrep --sarif` uses `sarif`.

`severityLimit` has `critical`, `high`, `medium`, and `low`. Each has `enabled` and `limit`, with the same count rule as Grype.

The severity comes from the SARIF property `security-severity` when a result or its rule has one. The value is a number from 0 to 10, or a numeric string. The ranges are the ones GitHub code scanning uses:

- 9.0 and above: critical
- 7.0 to 8.9: high
- 4.0 to 6.9: medium
- above 0 and below 4.0: low
- 0: none, and the severity limit does not count it

A result property wins over the same property on the rule. When neither is set, gatecheck uses the SARIF level. A missing result level uses the rule's `defaultConfiguration.level`, then `warning`.

- `error`: high
- `warning`: medium
- `note`: low
- `none`: the result is ignored

`ruleLimit` is the deny list. `ruleRiskAcceptance` is the allow list. Each has `enabled` and `rules`. A rule entry is `id` plus an optional `metadata.tags` list. `id` is compared without regard to case.

```yaml
sarif:
  ruleLimit:
    enabled: true
    rules:
      - id: CKV_AWS_21
        metadata:
          tags:
            - denied
  ruleRiskAcceptance:
    enabled: true
    rules:
      - id: B101
        metadata:
          tags:
            - accepted
```

See [Validation](./validation.md) for which results are counted and the order of the rules.

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

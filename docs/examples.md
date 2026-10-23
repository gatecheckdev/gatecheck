# Examples

## Config and one report

```shell
gatecheck config init > gatecheck.yaml
gatecheck validate --config gatecheck.yaml grype-report.json
```

The file from `config init` has every rule disabled, so this passes until you turn a rule on. For 80 percent line coverage, set `coverage.lineThreshold` to `0.8`.

## EPSS from a local file

```shell
gatecheck download epss > epss.csv
gatecheck list --epss --epss-filename epss.csv grype-report.json
```

## Bundle

The bundle name contains `bundle`. Each report name contains its type, and that base name becomes the label inside the bundle.

```shell
gatecheck bundle create gatecheck-bundle.tar.gz grype-report.json --tag ci
gatecheck bundle add gatecheck-bundle.tar.gz semgrep-report.json
gatecheck bundle add gatecheck-bundle.tar.gz gitleaks-report.json
gatecheck list gatecheck-bundle.tar.gz
gatecheck validate --config gatecheck.yaml gatecheck-bundle.tar.gz
```

## Audit

```shell
gatecheck validate --audit --config gatecheck.yaml grype-report.json
```

A threshold failure is printed and the process exits 0. A missing report still exits 255.

## Standard input

```shell
grype bkimminich/juice-shop:latest -o json | gatecheck list --input-type grype
```

## Several files

```shell
gatecheck list-all grype-report.json cyclonedx-report.json semgrep-report.json
```

`list-all` skips a coverage file such as `lcov.info`. List that file with `gatecheck list lcov.info`.

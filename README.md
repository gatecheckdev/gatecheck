# Gatecheck
[![CICD Pipeline](https://github.com/gatecheckdev/gatecheck/actions/workflows/run-test.yaml/badge.svg?branch=main)](https://github.com/gatecheckdev/gatecheck/actions/workflows/run-test.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/gatecheckdev/gatecheck.svg)](https://pkg.go.dev/github.com/gatecheckdev/gatecheck)
[![Go Report Card](https://goreportcard.com/badge/github.com/gatecheckdev/gatecheck)](https://goreportcard.com/report/github.com/gatecheckdev/gatecheck)


![Gatecheck Logo](static/gatecheck-logo-splash-dark.png)

Gatecheck automates report validation in a CI/CD Pipeline by comparing security findings to pre-determined thresholds.
It also provides report aggregation, artifact integrity, and deployment validation.
Gatecheck is stateless so self-hosting and provisioning servers is not required.

## Upcoming Features

The CLI is currently going through a much needed refactor.
Once all existing features have been implemented in the new CLI, the old one will be deprecated and then removed in
a few versions.

To enable the legacy CLI, set the variable `GATECHECK_FF_CLI_V1_ENABLED=1`.

## Getting Started

The fastest way to get started with Gatecheck is to download the pre-built binaries for your target system.

```shell
cd <target install dir>
curl -L <OS Specific Release>.tar.gz | tar xz
./gatecheck
./gatecheck --help
```

The Gatecheck CLI supports ```--help``` for every command for more detail usage.

Generate a configuration file with the default thresholds set

```shell
gatecheck config init > gatecheck.yaml
```

### Validation with Known Exploited Vulnerabilities (KEV) Catalog 

### Validation with Exploit Prediction Scoring System (EPSS) Scores

### Bundling Artifacts

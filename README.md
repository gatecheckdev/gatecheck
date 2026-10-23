# Gatecheck
[![CICD Pipeline](https://github.com/gatecheckdev/gatecheck/actions/workflows/run-test.yaml/badge.svg?branch=main)](https://github.com/gatecheckdev/gatecheck/actions/workflows/run-test.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/gatecheckdev/gatecheck.svg)](https://pkg.go.dev/github.com/gatecheckdev/gatecheck)
[![Go Report Card](https://goreportcard.com/badge/github.com/gatecheckdev/gatecheck)](https://goreportcard.com/report/github.com/gatecheckdev/gatecheck)

![Gatecheck Logo](https://static.gatecheck.dev/gatecheck-logo-splash-dark.png)

Gatecheck automates report validation in a CI/CD Pipeline by comparing security findings to pre-determined thresholds.
It also provides report aggregation, artifact integrity, and deployment validation.
Gatecheck is stateless so self-hosting and provisioning servers is not required.

![Gatecheck Version](https://static.gatecheck.dev/gatecheck-version.gif)

## Getting Started

The fastest way to get started with Gatecheck is to download the pre-built binaries for your target system.

```shell
cd <target install dir>
curl -L <OS Specific Release>.tar.gz | tar xz
./gatecheck --help
```

The Gatecheck CLI supports `--help` for every command.

Update a release binary in place. `--check` only prints the current and latest versions.

```shell
gatecheck update --check
gatecheck update
```

Generate a configuration file with the default thresholds. Every rule starts disabled, and coverage thresholds start at `0`.

```shell
gatecheck config init > gatecheck.yaml
```

Validate a report. The config is a flag. The report type comes from the filename, so a Grype report needs `grype` in the name.

```shell
gatecheck validate --config gatecheck.yaml grype-report.json
```

`gatecheck agent-guide` (alias `llm`) prints a markdown guide for coding agents. The same text is `docs/agent-guide.md`.

`gatecheck bootstrap` installs pinned Grype, Syft, Gitleaks, semgrep's experimental osemgrep CLI, Trivy, and osv-scanner. `gatecheck grype`, `gatecheck syft`, `gatecheck gitleaks`, `gatecheck semgrep`, `gatecheck osemgrep`, `gatecheck trivy`, and `gatecheck osv-scanner` run them.

### Summarize Reports with List

```shell
gatecheck ls --help
```

List with EPSS scores is supported for Grype, CycloneDX, Trivy, and osv-scanner reports.

![Gatecheck List](https://static.gatecheck.dev/gatecheck-list.gif)

### Validation

```shell
gatecheck validate --help
```

![Gatecheck Validate](https://static.gatecheck.dev/gatecheck-validate.gif)

### Bundling Artifacts

Bundling artifacts produces a gzipped tarball and a manifest. The bundle filename needs to contain `bundle` so `list` and `validate` treat it as a bundle.

```shell
gatecheck bundle create gatecheck-bundle.tar.gz grype-report.json
```

![Gatecheck Bundle](https://static.gatecheck.dev/gatecheck-bundle.gif)

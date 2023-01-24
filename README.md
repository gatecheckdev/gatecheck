# Gatecheck
[![CICD Pipeline](https://github.com/gatecheckdev/gatecheck/actions/workflows/run-test.yaml/badge.svg?branch=main)](https://github.com/gatecheckdev/gatecheck/actions/workflows/run-test.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/gatecheckdev/gatecheck.svg)](https://pkg.go.dev/github.com/gatecheckdev/gatecheck)
[![Go Report Card](https://goreportcard.com/badge/github.com/gatecheckdev/gatecheck)](https://goreportcard.com/report/github.com/gatecheckdev/gatecheck)


![Gatecheck Logo](static/gatecheck-logo.png)

Gatecheck automates report validation in a CI/CD Pipeline by comparing security findings to a pre-determined 
thresholds.
It also provides report aggregation, artifact integrity, and deployment validation.
Gatecheck is stateless so self-hosting and provisioning servers is not required.

## Upcoming Features

- [X] Report Aggregation
- [X] Vulnerability Threshold Configuration
- [X] Report Exporting
- [X] Asset bundling
- [X] Exploit Prediction Scoring System (EPSS) Querying
- [X] CISA Known Exploited Vulnerabilities (KEV) Blacklisting
- [ ] Artifact Integrity Verification
- [ ] Whitelist Management
- [ ] Deployment Verification & Validation

## Getting started

The fastest way to get started with Gatecheck is to download the pre-built binaries for your target system.

```shell
cd <target install dir>
curl -L <OS Specific Release>.tar.gz | tar xz
./gatecheck
./gatecheck --help
```

Gatecheck uses Cobra for the CLI, so the normal convention of using ```--help``` to see command usage works.

Generate a configuration file with the default thresholds set

```shell
gatecheck config init > gatecheck.yaml
```

Print scans in a table

```shell
gatecheck print grype-report.json gitleaks-report.json semgrep-report.json
Severity   | Package             | Version            | Link                                                        
-------------------------------------------------------------------------------------------------------------------
Critical   | curl                | 7.74.0-1.3+deb11u1 | https://security-tracker.debian.org/tracker/CVE-2021-22945  
Critical   | libcurl4            | 7.74.0-1.3+deb11u1 | https://security-tracker.debian.org/tracker/CVE-2021-22945  
...

Rule            | File                   | Secret                                              | Commit                                  
-----------------------------------------------------------------------------------------------------------------------------------------
jwt             | path/forgedJwt.spec.ts | eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIj...  | 1d1571854621f9fa4150e6fae93b24504d4e5a11
generic-api-key | path/totpSetup.spec.ts | IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH                    | 1d1571854621f9fa4150e6fae93b24504d4e5a11
...

Path              | Line | Level   | link                | CWE Message                                                                                   
--------------------------------------------------------------------------------------------------------
lib/insecurity.ts | 55   | WARNING | https://sg.run/4xN9 | CWE-798: Use of Hard-coded Credentials
lib/insecurity.ts | 53   | WARNING | https://sg.run/kXNo | CWE-522: Insufficiently Protected Credentials
...  
```

`print` command can also be used for gatecheck report and gatecheck config.

--------------- TODO --------------------
```shell
gatecheck validate grype-report.json

add table
```

``shell
gatecheck 
``

Add reports to the Gatecheck report

```shell
gatecheck add grype-report.json gitleaks-report.json semgrep-report.json
```


## Exporting

Exporting will take the report and upload it to a specific target location using the API.
Custom exporters can be created by simply implementing the Exporter interface.

```shell
gatecheck export defect-dojo grype grype-report.json
```

## Blacklist Validation
Gatecheck relies on [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities) to
provide blacklist validation.
You can take a Grype report and a CISA KEV blacklist file and see if any of the vulnerabilities are found in that Grype
report.

```shell
gatecheck validate --blacklist kev.json -c gatecheck.yaml grype-report.json
```

If `--audit` flag is used, it will exit code 0 after printing the report.
Otherwise, it will exit code 1 for a Validation Error.

### Defect Dojo

[Defect Dojo Documentation](https://defectdojo.github.io/django-DefectDojo/)

The Product Type, Product, and Engagement will be automatically created on export.
These variables must be supplied as environment variables.
Currently, the exporter uses the `/import-scan` endpoint in the Defect Dojo API

Environment Variables:
- GATECHECK_DD_API_KEY
- GATECHECK_DD_API_URL
- GATECHECK_DD_PRODUCT_TYPE
- GATECHECK_DD_PRODUCT
- GATECHECK_DD_ENGAGEMENT
- GATECHECK_DD_COMMIT_HASH
- GATECHECK_DD_BRANCH_TAG
- GATECHECK_DD_SOURCE_URL

## Types

With dozens of popular security and software tools, Gatecheck abstracts the terminology.

### Config

The configuration file has the threshold for each artifact.
The Gatecheck config (```gatecheck.yaml``` by default) is a customizable collection of tool specific configuration 
files.
This file is where the thresholds are set.

```shell
gatecheck config init
```

### Bundle

### Artifact

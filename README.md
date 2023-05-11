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
- [X] Artifact Integrity Verification
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

```shell
gatecheck validate -c gatecheck.yaml grype-report.json

grype validation failed: Critical (22 found > 0 allowed), High (27 found > 0 allowed)
Error: validation
```

Using the `--audit` flag will exit with code 0

### Validation with KEV Catalog 

Use the `-k` flag to provide a [CISA Known Exploited Vulnerabilities Catalog (JSON)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

```shell
gatecheck validate -c gatecheck.yaml -k known-exploited-vulnerabilities.json grype-report.json

grype validation failed: Critical (22 found > 0 allowed), High (27 found > 0 allowed)
Blacklisted Vulnerabilities Report
Catalog Version: 2022.11.08
0 Blacklisted Vulnerabilities Matched

0 Vulnerabilities listed on CISA Known Exploited Vulnerabilities Blacklist
Error: validation
```

### EPSS

Automatically queries the [Exploit Prediction Scoring System, by First](https://www.first.org/epss/) API and cross reference
using a Grype Report file.

```shell
CVE              | Severity   | EPSS   | Percentile | Date       | Link
---------------------------------------------------------------------------------------------------------------------------------
CVE-2011-3389    | Medium     | 40.95% | 98.22%     | 2023-01-23 | https://security-tracker.debian.org/tracker/CVE-2011-3389
CVE-2011-3389    | Medium     | 40.95% | 98.22%     | 2023-01-23 | https://security-tracker.debian.org/tracker/CVE-2011-3389
CVE-2022-0778    | High       | 35.45% | 97.80%     | 2023-01-23 | https://security-tracker.debian.org/tracker/CVE-2022-0778
CVE-2022-1271    | Unknown    | 25.98% | 96.99%     | 2023-01-23 | https://security-tracker.debian.org/tracker/CVE-2022-1271
CVE-2018-25032   | High       | 23.44% | 96.63%     | 2023-01-23 | https://security-tracker.debian.org/tracker/CVE-2018-25032
CVE-2022-23852   | Critical   | 20.15% | 96.32%     | 2023-01-23 | https://security-tracker.debian.org/tracker/CVE-2022-23852
CVE-2022-23990   | Critical   | 19.17% | 96.23%     | 2023-01-23 | https://security-tracker.debian.org/tracker/CVE-2022-23990
CVE-2022-25315   | Critical   | 17.17% | 96.07%     | 2023-01-23 | https://security-tracker.debian.org/tracker/CVE-2022-25315
...
```

## Exporting

Exporting will take the report and upload it to a specific target location using the API.
Custom exporters can be created by simply implementing the Exporter interface.

### DefectDojo

[DefectDojo Documentation](https://defectdojo.github.io/django-DefectDojo/)

The Product Type, Product, and Engagement will be automatically created on export.
These variables must be supplied as environment variables.
Currently, the exporter uses the `/import-scan` endpoint in the DefectDojo API.

Environment Variables:
- GATECHECK_DD_API_KEY
- GATECHECK_DD_API_URL
- GATECHECK_DD_PRODUCT_TYPE
- GATECHECK_DD_PRODUCT
- GATECHECK_DD_ENGAGEMENT
- GATECHECK_DD_COMMIT_HASH
- GATECHECK_DD_BRANCH_TAG
- GATECHECK_DD_SOURCE_URL
- GATECHECK_DD_TAGS

```shell
gatecheck export defect-dojo grype-report.json
```

### AWS S3

[Developer Guide | AWS SDK for Go V2](https://aws.github.io/aws-sdk-go-v2/docs/)

The AWS S3 upload bucket name must be supplied as an environment variable, `AWS_BUCKET`.
To upload artifacts to S3, ensure the configured `AWS_PROFILE` has write access to `AWS_BUCKET`.
Currently, the exporter uses the AWS SDK for Go V2 to upload artifacts to AWS S3.

Environment Variables:
- AWS_BUCKET
- AWS_PROFILE

```shell
gatecheck export s3 grype-report.json \
  --key upload/path/to/grype-report.json
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


### Config

The configuration file has the threshold for each artifact.
The Gatecheck config (```gatecheck.yaml``` by default) is a customizable collection of tool specific configuration 
files.
This file is where the thresholds are set.

```shell
gatecheck config init > gatecheck.yaml
cat gatecheck.yaml

grype:
    critical: -1
    high: -1
    medium: -1
    low: -1
    negligible: -1
    unknown: -1
semgrep:
    info: -1
    warning: -1
    error: -1
gitleaks:
    SecretsAllowed: false
```

### Bundle

Artifacts and generic files can be bundled using Gatecheck.
The files are compressed which reduces the total file size while preserving data.

To create a new bundle
```shell
gatecheck bundle -o bundle.gatecheck grype-report.json semgrep-sast-report.json random.file
```

To view the files in a bundle
```shell
gatecheck print bundle.gatecheck

Type         | Label                    | Digest                                                           | Size
---------------------------------------------------------------------------------------------------------------------
Grype        | grype-report.json        | 588E5969C6205FFD3F5531EB643B6D6BB9FF4CBB862BD9BC180DC2867D3A1A18 | 940 kB
Semgrep      | semgrep-sast-report.json | 377C6C86987DFB649266432DF2A741917EC7D225CA883A6ABDC176AA44519F84 | 172 kB
Gitleaks     |                          |                                                                  | 0 B
Generic File | random.file              | 1C87B6727F523662DF714F06A94EA27FA4D9050C38F4F7712BD4663FFBFDFA01 | 13 B

                                                                                                Total Size: 1.1 MB
```

To validate all files in the bundle with a configuration file

```shell
gatecheck validate -c gatecheck.yaml bundle.gatecheck
```

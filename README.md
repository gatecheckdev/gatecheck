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
- [X] Whitelist Management
- [ ] Deployment Verification & Validation

## Getting Started

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
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Severity   │ Package               │ Version          │ Link                                                         │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Critical   │ vm2                   │ 3.9.17           │ https://github.com/advisories/GHSA-cchq-frgv-rjh5            │
│ Critical   │ vm2                   │ 3.9.17           │ https://github.com/advisories/GHSA-whpj-8f3w-67p5            │
│ Critical   │ marsdb                │ 0.6.11           │ https://github.com/advisories/GHSA-5mrr-rgp6-x4gr            │
│ Critical   │ jsonwebtoken          │ 0.1.0            │ https://github.com/advisories/GHSA-c7hr-j4mj-j2w6            │
...

┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Rule            │ File                                                           │ secret                                             │ Commit                                   │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ generic-api-key │ .travis.yml                                                    │ ...f53beaa4f097b5a49754c4edb8e95d59088bac519607637 │ 8a474274d6fa9335c23fe1ca2dc19688e7dffac5 │
│ jwt             │ cypress/integration/e2e/forgedJwt.spec.ts                      │ ...fQ.gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8' │ 1d1571854621f9fa4150e6fae93b24504d4e5a11 │
│ jwt             │ cypress/integration/e2e/forgedJwt.spec.ts                      │ ...fQ.gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8" │ cb7bddb172d7d01e6403c8551689c3e0a7fb47bf │
│ generic-api-key │ cypress/integration/e2e/totpSetup.spec.ts                      │ IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH                   │ 1d1571854621f9fa4150e6fae93b24504d4e5a11 │
│ generic-api-key │ cypress/integration/e2e/totpSetup.spec.ts                      │ IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH                   │ b19993bcee5587459474fc495f35977f542d26e8 │
...

┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Severity │ Path                           │ Line  │ CWE Message                                                                                      │ Link                │
├────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ ERROR    │ frontend/src/...guard.spec.ts  │ 40    │ [CWE-321: Use of Hard-coded Cryptographic Key]                                                   │ https://sg.run/05N5 │
│ ERROR    │ frontend/src/...onent.spec.ts  │ 50    │ [CWE-321: Use of Hard-coded Cryptographic Key]                                                   │ https://sg.run/05N5 │
│ ERROR    │ frontend/src/...onent.spec.ts  │ 56    │ [CWE-321: Use of Hard-coded Cryptographic Key]                                                   │ https://sg.run/05N5 │
│ ERROR    │ data/static/users.yml          │ 150   │ [CWE-798: Use of Hard-coded Credentials]                                                         │ https://sg.run/l2o5 │
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
Or `--fetch-kev` to query the API without a file

```shell
gatecheck validate -c gatecheck.yaml -k known-exploited-vulnerabilities.json grype-report.json

grype validation failed: Critical (22 found > 0 allowed), High (27 found > 0 allowed)
Blacklisted Vulnerabilities Report
Catalog Version: 2022.11.08
0 Blacklisted Vulnerabilities Matched

0 Vulnerabilities listed on CISA Known Exploited Vulnerabilities Blacklist
Error: validation
```

### Settings
Settings can be applied with environment variables or using a settings.env file

To see the applied settings
```shell
gatecheck config info
```
expected file: `settings.env`

```shell
GATECHECK_AWS_PROFILE=
GATECHECK_DD_COMMIT_HASH=
GATECHECK_DD_TAGS=
GATECHECK_AWS_BUCKET=
GATECHECK_DD_BRANCH_TAG=
GATECHECK_DD_SOURCE_URL=
GATECHECK_DD_API_URL=
GATECHECK_DD_API_KEY=
GATECHECK_DD_PRODUCT_TYPE=
GATECHECK_DD_ENGAGEMENT=
GATECHECK_KEV_URL='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
GATECHECK_DD_PRODUCT=
GATECHECK_EPSS_URL='https://epss.cyentia.com'
```

### EPSS

Automatically queries the [Exploit Prediction Scoring System, by First](https://www.first.org/epss/) API and cross reference
using a Grype Report file.

```shell
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ CVE                 │ Severity   │ EPSS Score │ Percentile │ Link                                                         │
├───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ CVE-2019-1010024    │ Negligible │ 0.02258    │ 88.09%     │ https://security-tracker.debian.org/tracker/CVE-2019-1010024 │
│ GHSA-jf85-cpcp-j695 │ Critical   │ 0.01552    │ 85.44%     │ https://github.com/advisories/GHSA-jf85-cpcp-j695            │
│ CVE-2019-1010023    │ Negligible │ 0.01081    │ 82.35%     │ https://security-tracker.debian.org/tracker/CVE-2019-1010023 │
│ GHSA-p6mc-m468-83gw │ High       │ 0.01036    │ 81.94%     │ https://github.com/advisories/GHSA-p6mc-m468-83gw            │
│ CVE-2010-4756       │ Negligible │ 0.00824    │ 79.68%     │ https://security-tracker.debian.org/tracker/CVE-2010-4756    │
│ GHSA-c7hr-j4mj-j2w6 │ Critical   │ 0.00659    │ 76.83%     │ https://github.com/advisories/GHSA-c7hr-j4mj-j2w6            │
│ GHSA-c7hr-j4mj-j2w6 │ Critical   │ 0.00659    │ 76.83%     │ https://github.com/advisories/GHSA-c7hr-j4mj-j2w6            │
│ CVE-2007-6755       │ Negligible │ 0.00614    │ 75.93%     │ https://security-tracker.debian.org/tracker/CVE-2007-6755    │
│ CVE-2007-6755       │ Negligible │ 0.00614    │ 75.93%     │ https://security-tracker.debian.org/tracker/CVE-2007-6755    │
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

### Config

The configuration file has the threshold for each artifact.
The Gatecheck config (`gatecheck.yaml` by default) is a customizable collection of tool specific configuration 
files.
This file is where the thresholds are set.

```shell
gatecheck config init > gatecheck.yaml
cat gatecheck.yaml

cyclonedx:
    allowList:
        - id: example allow id
          reason: example reason
    denyList:
        - id: example deny id
          reason: example reason
    required: false
    critical: -1
    high: -1
    medium: -1
    low: -1
    info: -1
    none: -1
    unknown: -1
gitleaks:
    secretsAllowed: true
grype:
    allowList:
        - id: example allow id
          reason: example reason
    denyList:
        - id: example deny id
          reason: example reason
    epssAllowThreshold: 1
    epssDenyThreshold: 1
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
```

### Bundle

Artifacts and generic files can be bundled using Gatecheck.
The files are compressed which reduces the total file size while preserving data.
The resulting file is a gatecheck-bundle.tar.gz file

To create a new bundle

```shell
gatecheck bundle grype-report.json semgrep-sast-report.json
```

To view the files in a bundle

```shell
gatecheck print bundle.gatecheck
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Type                      │ Label                    │ Digest                                                           │ Size   │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Semgrep Scan Report       │ semgrep-sast-report.json │ 2423f27d67cc9e2aeabc83c0b47e1fe30ddcc23846e17e29e611ea4206b39326 │ 265 kB │
│ Anchore Grype Scan Report │ grype-report.json        │ 4f90f3faf608d854def3d6c9ac014200af7dff81ea8b177e5093baf4d76c07fe │ 232 kB │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

To validate all files in the bundle with a configuration file

```shell
gatecheck validate -c gatecheck.yaml bundle.gatecheck
```

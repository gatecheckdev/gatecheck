# VEX

A VEX (Vulnerability Exploitability eXchange) document says whether a vulnerability actually affects your software. `validate` reads OpenVEX and CycloneDX VEX files and skips the findings they mark as not exploitable. Your risk decisions can then live in a VEX file that other tools also read, not only in the `cveRiskAcceptance` lists in the gatecheck config.

```shell
gatecheck validate --config gatecheck.yaml --vex app.openvex.json grype-report.json
gatecheck validate --vex app.openvex.json --vex vendor.cdx.json trivy-report.json
```

VEX applies to Grype, CycloneDX, Trivy, and osv-scanner reports, and to those reports inside a bundle. SARIF, Semgrep, Gitleaks, and coverage reports are not affected.

## Where the files come from

- `--vex FILE` on `validate`. Repeat the flag for more files.
- `GATECHECK_VEX`, a comma-separated list of files. It is read only when `--vex` is not given.
- `vex.files` in the config. These are read along with the flag or environment files.

```yaml
vex:
  files:
    - .vex/app.openvex.json
```

Relative paths are read from the working directory. A file that is missing, is not JSON, or is neither format is an error, and `validate` exits 2 without checking the report, even with `--audit`.

## Which statuses skip a finding

| Format | Skips the finding | Keeps the finding |
| --- | --- | --- |
| OpenVEX `status` | `not_affected`, `fixed` | `affected`, `under_investigation` |
| CycloneDX `analysis.state` | `not_affected`, `false_positive`, `resolved`, `resolved_with_pedigree` | `exploitable`, `in_triage` |

A CycloneDX vulnerability with no `analysis` is ignored.

## Matching a statement to a finding

A statement matches a finding when one of its ids matches one of the finding's ids, without regard to case.

- OpenVEX ids are `vulnerability.name`, `vulnerability.@id`, and `vulnerability.aliases`. The older form, where `vulnerability` is a plain string, also works.
- CycloneDX ids are the vulnerability `id` and its `references[].id`.
- Finding ids are the Grype vulnerability id plus `relatedVulnerabilities`, the CycloneDX id plus its references, Trivy's `VulnerabilityID` plus `VendorIDs`, and the osv-scanner id plus its aliases.

A statement can also name packages, as package URLs (purls):

- OpenVEX: the `subcomponents` of each product, or the older statement-level `subcomponents`. Each one is an `@id` or `identifiers.purl`.
- CycloneDX: the `affects[].ref` entries. A ref is looked up in the document's components to find its purl. A ref that is already a purl is used as-is.

When a statement names packages, it matches only findings in one of them. The purl type, namespace, and name have to be equal. The version has to be equal too when the statement's purl has one. Qualifiers such as `?arch=amd64` and subpaths are ignored. When a statement names no packages, or the finding has no purl, the id alone decides.

gatecheck does not check the OpenVEX product itself, such as `pkg:oci/app@sha256:...`. It does not know which product the report was made from. Keep one VEX file per product, and pass the one that goes with the report.

Finding purls come from Grype `artifact.purl`, the CycloneDX component for each `affects` ref, and Trivy `PkgIdentifier.PURL`. For osv-scanner they are built from the ecosystem, name, and version, for Go, npm, PyPI, crates.io, Maven, RubyGems, NuGet, Packagist, Pub, and Hex. A CycloneDX vulnerability that affects several packages is skipped only when every one of them is covered.

When several statements match a finding, the one with the latest timestamp decides. The timestamp is `last_updated` or `timestamp` on the statement, then on the document. For CycloneDX it is `analysis.lastUpdated`, then `updated`, `analysis.firstIssued`, `published`, and `metadata.timestamp`. Ties go to the statement read last. An `affected` statement dated after a `not_affected` one puts the finding back.

## Where VEX runs in validation

VEX runs right after the CVE deny list and alongside `cveRiskAcceptance`. See [Validation](./validation.md).

- A `cveLimit` deny list entry still fails the report, even when a VEX file says the CVE is not exploitable.
- A finding that VEX skips is not counted by the KEV limit, the EPSS rules, or the severity limits.

Each skipped finding is logged at info level with its id, the VEX status, the justification, and the file it came from.

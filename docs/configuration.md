# Configuration

Gatecheck uses configuration files to define validation rules for security reports. These files can be in YAML, JSON, or TOML format. The configuration specifies thresholds, limits, and risk acceptances for various report types, allowing you to customize validation to your project's security requirements.

## Creating a Configuration File

To generate a default configuration file, use the CLI:

```
gatecheck config new config.yaml
```

This creates a file with all fields set to default values (mostly disabled with zero limits). You can then edit it to enable rules and set appropriate values.

Configs support three formats:
- YAML (.yaml or .yml)
- JSON (.json)
- TOML (.toml)

The structure is the same across formats. Below is a detailed explanation of each section and field, based on the Gatecheck codebase.

## Top-Level Fields

- **version** (string): The configuration version. Currently "1". Reserved for future schema changes.
  
- **metadata** (object): Arbitrary metadata that doesn't affect validation.
  - **tags** (array of strings): Custom tags for organization or notes, e.g., ["auto-generated", "prod-config"].

## Grype Configuration

This section defines rules for Grype vulnerability reports.

- **severityLimit** (object): Sets limits on the number of vulnerabilities per severity level. Exceeding a limit fails validation.
  - **critical/high/medium/low** (objects):
    - **enabled** (boolean): Whether this limit is active.
    - **limit** (unsigned integer): Maximum allowed vulnerabilities of this severity.

- **epssLimit** (object): Fails validation if any vulnerability's EPSS score exceeds this limit.
  - **enabled** (boolean): Activate this rule.
  - **score** (float): Maximum allowed EPSS score (0.0 to 1.0).

- **kevLimitEnabled** (boolean): If true, fails validation if any vulnerability matches the Known Exploited Vulnerabilities (KEV) catalog.

- **cveLimit** (object): Fails validation if any specified CVE is present.
  - **enabled** (boolean): Activate this rule.
  - **cves** (array of objects):
    - **id** (string): The CVE ID (e.g., "CVE-2024-1234").
    - **metadata** (object):
      - **tags** (array of strings): Optional tags for the CVE.

- **epssRiskAcceptance** (object): Skips validation for vulnerabilities with EPSS scores below this threshold (risk accepted).
  - **enabled** (boolean): Activate this rule.
  - **score** (float): Minimum EPSS score for validation; lower scores are accepted.

- **cveRiskAcceptance** (object): Skips validation for specified CVEs (risk accepted).
  - **enabled** (boolean): Activate this rule.
  - **cves** (array of objects): Same structure as in cveLimit.

**Example (YAML):**
```yaml
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
  cveLimit:
    enabled: true
    cves:
      - id: CVE-2023-1234
        metadata:
          tags: ["critical"]
  epssRiskAcceptance:
    enabled: true
    score: 0.1
  cveRiskAcceptance:
    enabled: true
    cves:
      - id: CVE-2023-5678
```

**Use Case:** Enforce zero critical vulnerabilities but allow up to 5 high ones, while accepting low-EPSS risks.

## Cyclonedx Configuration

Identical structure to Grype. Applies to CycloneDX SBOM reports with vulnerabilities.

**Example:** Same as Grype section above, under `cyclonedx`.

## Semgrep Configuration

For Semgrep SAST reports.

- **severityLimit** (object): Limits on findings per severity.
  - **error/warning/info** (objects):
    - **enabled** (boolean)
    - **limit** (unsigned integer)

- **impactRiskAcceptance** (object): Accepts findings based on impact level.
  - **enabled** (boolean): Activate this rule.
  - **high/medium/low** (booleans): If true, accept findings of that impact level.

**Example (YAML):**
```yaml
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
```

**Use Case:** Fail on any errors, allow up to 10 warnings, and accept all medium/low impact findings.

## Gitleaks Configuration

For Gitleaks secret detection reports.

- **limitEnabled** (boolean): If true, fails validation if any non-ignored secrets are found.

**Example (YAML):**
```yaml
gitleaks:
  limitEnabled: true
```

**Use Case:** Ensure no secrets are leaked in the codebase.

## Coverage Configuration

For LCOV code coverage reports.

- **lineThreshold** (float): Minimum required line coverage percentage (0-100).
- **functionThreshold** (float): Minimum required function coverage percentage.
- **branchThreshold** (float): Minimum required branch coverage percentage.

**Example (YAML):**
```yaml
coverage:
  lineThreshold: 80.0
  functionThreshold: 75.0
  branchThreshold: 70.0
```

**Use Case:** Enforce minimum test coverage levels in CI/CD pipelines.

## Full Example Configuration (YAML)

```yaml
version: "1"
metadata:
  tags: ["project-x", "v1.0"]

grype:
  # ... (as above)

cyclonedx:
  # ... (similar to grype)

semgrep:
  # ... (as above)

gitleaks:
  limitEnabled: true

coverage:
  lineThreshold: 80.0
  # ... (as above)
```

## Tips for Writing Configurations

- Start with the default generated file and enable rules incrementally.
- Use risk acceptance to grandfather in known issues while enforcing stricter rules for new vulnerabilities.
- Integrate with CI/CD: Validate in pipelines to block merges/deployments if rules fail.
- Formats are interchangeable; choose based on your ecosystem (e.g., YAML for Kubernetes-heavy projects).
- Validation follows a specific order of precedence (see Validation docs).

For more details, refer to the source code in `pkg/gatecheck/config.go`.
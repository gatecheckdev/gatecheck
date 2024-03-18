# Configuration

## Header

```yaml
# The configuration version, reserved for future use but not required in v1
version: "1"
# Option metadata for the config that doesn't impact functionality
metadata:
  tags:
    - auto generated from CLI
```

## Grype Configuration

```yaml
grype:
  # Severity Limit Rule sets a limit for how many vulnerabilities are allowed in a report
  # each severity level can have a different limit
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
  # EPSS Limit Rule sets a limit for the max score allowed for each vulnerability
  epssLimit:
    enabled: false
    score: 0
  # KEV Limit Rule fails validation if any vulnerability matches to the 
  # Known Exploited Vulnerability Catalog
  kevLimitEnabled: false
  # CVE Limit Rule fails validation if any vulnerability ID matches
  # to any CVE in this list
  cveLimit:
    enabled: false
    cves: 
      - ID: CVE-example-2024-1
        Metadata:
          Tags:
            - Some example tag
  # EPSS Risk Acceptance Rule skips validation for vulnerabilities with 
  # EPSS score less than this score limit
  epssRiskAcceptance:
    enabled: false
    score: 0
  # CVE Risk Acceptance Rule skips validation for vulnerability ID that matches
  cveRiskAcceptance:
    enabled: false
    cves: 
      - ID: CVE-example-2024-2
        Metadata:
          Tags:
            - Some example tag
```

## Cyclonedx Configuration

```yaml
cyclonedx:
  # Severity Limit Rule sets a limit for how many vulnerabilities are allowed in a report
  # each severity level can have a different limit
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
  # EPSS Limit Rule sets a limit for the max score allowed for each vulnerability
  epssLimit:
    enabled: false
    score: 0
  # KEV Limit Rule fails validation if any vulnerability matches to the 
  # Known Exploited Vulnerability Catalog
  kevLimitEnabled: false
  # CVE Limit Rule fails validation if any vulnerability ID matches
  # to any CVE in this list
  cveLimit:
    enabled: false
    cves: []
  # EPSS Risk Acceptance Rule skips validation for vulnerabilities with 
  # EPSS score less than this score limit
  epssRiskAcceptance:
    enabled: false
    score: 0
  # CVE Risk Acceptance Rule skips validation for vulnerability ID that matches
  cveRiskAcceptance:
    enabled: false
    cves: []
```

## Semgrep Configuration

```yaml
semgrep:
  # Severity Limits can be applied for each level
  # if there are findings than the limit permits,
  # It will result in validation failure
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
  # Impact Risk Acceptance premits findings based
  # on their impact level
  impactRiskAcceptance:
    enabled: false
    high: false
    medium: false
    low: false
```

## GitLeaks Configuration

GitLeaks secrets detection validation can be turned on or off.
When the limit is enabled, the presence of any non-ignored finding will result in a validation failure.

```yaml
gitleaks:
  limitEnabled: false
```

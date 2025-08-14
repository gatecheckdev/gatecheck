# CLI Reference

This section provides a detailed reference for all Gatecheck CLI commands, including subcommands, options, examples, and use cases.

## gatecheck

The root command. Displays help information.

**Usage:**
```
gatecheck [command]
```

**Use Case:** Entry point to access all functionalities. Run without arguments to see available commands.

## gatecheck bundle

Manage Gatecheck bundles (.gcb files) which aggregate multiple security reports.

### gatecheck bundle new

Create a new empty bundle file.

**Usage:**
```
gatecheck bundle new <bundle-file>
```

**Example:**
```
gatecheck bundle new myproject.gcb
```

**Use Case:** Initialize a new bundle before adding reports, useful for starting a new attestation or archive.

### gatecheck bundle add

Add a report to an existing bundle.

**Usage:**
```
gatecheck bundle add <bundle-file> <report-file> --type <report-type>
```

**Options:**
- `--type`: Specify report type (e.g., grype, cyclonedx, semgrep, gitleaks)

**Example:**
```
gatecheck bundle add myproject.gcb grype-report.json --type grype
```

**Use Case:** Aggregate reports from different tools into one file for easy sharing, auditing, or CI/CD integration.

### gatecheck bundle list

List the contents of a bundle.

**Usage:**
```
gatecheck bundle list <bundle-file>
```

**Example:**
```
gatecheck bundle list myproject.gcb
```

**Use Case:** Quickly inspect what reports are in a bundle without extracting them, helpful for verification.

## gatecheck config

Manage configuration files for validation.

### gatecheck config new

Generate a new default configuration file.

**Usage:**
```
gatecheck config new <config-file> [--format yaml|json|toml]
```

**Example:**
```
gatecheck config new gatecheck.yaml
```

**Use Case:** Create a starting point for defining validation rules, then customize thresholds for your project.

## gatecheck download

Download external datasets like EPSS or KEV.

**Usage:**
```
gatecheck download <type> <output-file>
```

**Types:** epss, kev

**Example:**
```
gatecheck download epss epss_scores.csv
```

**Use Case:** Fetch latest vulnerability scoring data for offline use in validation or analysis.

## gatecheck list

List contents of a report or bundle in a human-readable format.

**Usage:**
```
gatecheck list <file> [--input-type <type>]
```

**Example:**
```
gatecheck list grype-report.json
```

**Use Case:** Summarize lengthy JSON reports for quick review, e.g., checking vulnerability counts without parsing JSON manually.

## gatecheck validate

Validate reports against a configuration file.

**Usage:**
```
gatecheck validate <config-file> <target-file>
```

**Example:**
```
gatecheck validate gatecheck.yaml bundle.gcb
```

**Use Case:** Ensure security reports meet project thresholds before deployment, integrating into CI pipelines for automated checks.

## gatecheck version

Print the version information.

**Usage:**
```
gatecheck version
```

**Example:**
```
gatecheck version
```

**Use Case:** Verify the installed version for compatibility or reporting issues.
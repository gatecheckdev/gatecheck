# Validation

Gatecheck validates reports against a config file.

## Command

```
gatecheck validate config.yaml report.json
```

Or with bundle:

```
gatecheck validate config.yaml bundle.gcb
```

## Rules Precedence

1. CVE Limit
2. CVE Risk Acceptance
3. KEV Limit
4. EPSS Risk Acceptance
5. EPSS Limit
6. Severity Limit

See Configuration for details.
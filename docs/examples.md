# Examples

## Basic Usage

Bundle reports:

```
gatecheck bundle new mybundle.gcb
gatecheck bundle add mybundle.gcb grype.json --type grype
```

Validate:

```
gatecheck validate config.yaml mybundle.gcb
```
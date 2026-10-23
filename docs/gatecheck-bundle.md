# Gatecheck Bundle

A bundle is a gzipped tar with a JSON manifest. It holds the report bytes, a SHA-256 digest, and any tags you set. The suggested name is `gatecheck-bundle.tar.gz`. `validate` treats the file as a bundle when the name contains `bundle`. `list` does that too, and also when the name contains `gatecheck`. `project.gcb` is rejected by both commands.

## Create

```shell
gatecheck bundle create gatecheck-bundle.tar.gz grype-report.json --tag ci
```

`bundle init` is the same command. The label stored in the manifest is the base name of the target file. That label is what `validate` uses later to pick the report type, so the file needs a word such as `grype` or `semgrep` in its name.

Repeat `--tag` for more than one tag. When the flag is omitted, `GATECHECK_BUNDLE_TAG` is read as a comma-separated list.

## Add

```shell
gatecheck bundle add gatecheck-bundle.tar.gz semgrep-report.json
gatecheck bundle add gatecheck-bundle.tar.gz gitleaks-report.json --tag audit
```

The bundle file has to exist already.

## Remove

```shell
gatecheck bundle remove gatecheck-bundle.tar.gz semgrep-report.json
```

`bundle rm` is the same command. The second argument is the label. A label that is not in the bundle is logged, and the command exits 0.

## Inspect

There is no `bundle list` subcommand. List the manifest with `list`:

```shell
gatecheck list gatecheck-bundle.tar.gz
```

The table columns are label, digest, tags, and size.

## Validate

```shell
gatecheck validate --config gatecheck.yaml gatecheck-bundle.tar.gz
```

Each label is checked on its own with the same rules as a standalone file. Labels that do not match a supported type are skipped, including Syft. A Grype failure and a Semgrep failure in the same bundle are both reported, and the command exits 1.

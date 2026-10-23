# Gatecheck Bundle

A bundle is a gzipped tar with a JSON manifest. It holds the report bytes, a SHA-256 digest, and any tags you set. The suggested name is `gatecheck-bundle.tar.gz`. `list` and `validate` treat a file as a bundle when the gzipped tar contains `gatecheck-manifest.json`. When the contents are ambiguous, `validate` still requires `bundle` in the name, and `list` also accepts `gatecheck`.

## Create

```shell
gatecheck bundle create gatecheck-bundle.tar.gz grype-report.json --tag ci
```

`bundle init` is the same command. The label stored in the manifest is the base name of the target file. `validate` reads each stored file's contents to pick the type, and uses the label only when the contents are ambiguous. A CycloneDX file stored as `grype.json` is still validated as CycloneDX.

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

Each stored file is checked on its own with the same rules as a standalone file. Files that do not match a supported type are skipped, including Syft JSON. A Grype failure and a Semgrep failure in the same bundle are both reported, and the command exits 1.

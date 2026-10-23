# Supported Reports

`list` and `validate` pick a report type from the file contents. The filename is used only when the contents do not identify a type.

Content rules, in this order:

1. A gzipped tar that contains `gatecheck-manifest.json` is a Gatecheck bundle.
2. `bomFormat` of `CycloneDX` is CycloneDX JSON. This wins when the name contains `grype` or `syft`, and it wins when the tool that wrote the BOM was Grype, Syft, Trivy, or another tool.
3. SARIF 2.1.0. The top-level `version` is the string `2.1.0` and `runs` is an array. A `$schema` that mentions SARIF is enough when `runs` is missing or null.
4. Grype JSON. `descriptor.name` is `grype`, or `matches` is a non-empty array of objects with `vulnerability` and `artifact`.
5. Syft JSON. `descriptor.name` is `syft`, or `schema.url` points at the Syft schema. `list` and `validate` then return an error. Syft JSON is not implemented. A Syft CycloneDX BOM is CycloneDX, not Syft.
6. Semgrep JSON. `results` is an array of objects with `check_id`, or `results` and `errors` are both arrays. Semgrep's SARIF output is SARIF, not this type.
7. Gitleaks JSON. A non-empty array of objects with `RuleID` and one of `File`, `Commit`, or `Fingerprint`.
8. LCOV text. A line starts with `SF:` and the file also has `DA:`, `LF:`, or `end_of_record`.
9. Clover XML. An XML document with `clover=` or a `<clover` element.
10. Cobertura XML. An XML document with `line-rate=`.

CycloneDX XML is not read. The CycloneDX support is JSON.

When none of those match, the filename is checked. The match is a lowercase substring, and the first match wins:

1. `grype`
2. `cyclonedx`
3. `semgrep`
4. `gitleaks`
5. `syft`
6. `sarif`
7. `bundle`. `list` also accepts a name containing `gatecheck`. `validate` requires the word `bundle` for this fallback. A real bundle is still detected from its contents when the name is `project.gcb`.
8. Coverage, when the name contains `lcov`, `clover`, `cobertura`, or `coverage`, or when it ends in `.info`.

The filename match is case sensitive. `Grype-report.json` is not a filename match. A Grype report is still recognized from its contents when `descriptor.name` is `grype`.

An empty Grype document such as `{"matches":[]}` does not identify itself. The filename is what selects it. The same is true of `{"results":[]}` and `[]`.

Coverage format when the name is the only signal, checked in this order:

- The name contains `lcov`, or ends in `.info`: LCOV.
- The name contains `clover`: Clover XML.
- The name ends in `.xml`: Cobertura XML.

A name that only contains `coverage`, such as `coverage.json`, is selected as coverage and then fails, because the format is not one of those three and the contents did not identify one.

From standard input, `list` still requires `--input-type`, so the command does not wait on a terminal. The value is matched as if it were a filename called `stdin:<value>`, and only when the contents are ambiguous. Clear contents win over `--input-type`.

```shell
grype bkimminich/juice-shop:latest -o json | gatecheck list --input-type grype
```

`list-all` lists a file when the contents or the name identify Grype, Semgrep, Gitleaks, Syft, CycloneDX, SARIF, or a bundle. Coverage files are skipped with a warning. There is no `--input-type` flag on `list-all`.

Inside a bundle, `validate` uses the same content rules on each stored file, and falls back to the label. The label is the base name of the file you added. Labels that still do not match are skipped. Syft JSON inside a bundle is skipped.

What each command can do:

| Report | list | validate | bundle |
| --- | --- | --- | --- |
| Grype | yes | yes | yes |
| CycloneDX JSON | yes | yes | yes |
| SARIF 2.1.0 | yes | yes | yes |
| Semgrep JSON | yes | yes | yes |
| Gitleaks | yes | yes | yes |
| LCOV, Clover, Cobertura | yes | yes | yes |
| Syft JSON | error | error | the file is stored, and validation skips that label |
| Bundle | when the contents are a bundle, or the name contains `bundle` or `gatecheck` | when the contents are a bundle, or the name contains `bundle` | yes, as an ordinary file |

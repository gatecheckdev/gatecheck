# Supported Reports

`list` and `validate` pick a report type by looking for a lowercase word in the filename. The first match in this list wins:

1. `grype`: Anchore Grype JSON.
2. `cyclonedx`: CycloneDX JSON that includes vulnerabilities.
3. `semgrep`: Semgrep JSON.
4. `gitleaks`: Gitleaks JSON (a list of findings).
5. `syft`: the name is recognized. `list` and `validate` both return an error. Syft is not implemented.
6. `bundle`: a Gatecheck bundle. `list` also accepts a name containing `gatecheck`. `validate` requires the word `bundle`. `project.gcb` matches neither rule.
7. Coverage, when the name contains `lcov`, `clover`, `cobertura`, or `coverage`, or when it ends in `.info`.

The match is case sensitive. `Grype-report.json` and `CycloneDX.json` are rejected.

Coverage file format, checked in this order:

- The name contains `lcov`, or ends in `.info`: LCOV.
- The name contains `clover`: Clover XML.
- The name ends in `.xml`: Cobertura XML.

A name that only contains `coverage`, such as `coverage.json`, is selected as coverage and then fails, because the format is not one of those three.

From standard input, pass the same word to `--input-type`. The value is matched as if it were a filename called `stdin:<value>`.

```shell
grype bkimminich/juice-shop:latest -o json | gatecheck list --input-type grype
```

`list-all` is stricter. It lists a file only when the name contains `grype`, `semgrep`, `gitleaks`, `syft`, `cyclonedx`, `bundle`, or `gatecheck`. Coverage files are skipped with a warning. There is no `--input-type` flag on `list-all`.

Inside a bundle, `validate` uses the stored label, which is the base name of the file you added. A label has to contain the same words. Labels that do not match are skipped. Syft labels inside a bundle are skipped.

What each command can do:

| Report | list | validate | bundle |
| --- | --- | --- | --- |
| Grype | yes | yes | yes |
| CycloneDX | yes | yes | yes |
| Semgrep | yes | yes | yes |
| Gitleaks | yes | yes | yes |
| LCOV, Clover, Cobertura | yes | yes | yes |
| Syft | error | error | the file is stored, and validation skips that label |
| Bundle | when the name contains `bundle` or `gatecheck` | when the name contains `bundle` | yes, as an ordinary file |

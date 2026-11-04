# License gating

`validate` can fail an SBOM whose packages use licenses you do not want, such as GPL in a closed-source product, or packages with no license at all.

License rules read two kinds of report:

- Syft JSON (`syft -o syft-json` or `syft -o json`). Each `artifacts[]` entry is a package. Its licenses are each `spdxExpression`, or `value` when the expression is empty. Older Syft output, where `licenses` is a list of strings, also works.
- CycloneDX JSON. Each component, including nested `components`, is a package. Its licenses are each `licenses[].expression`, `licenses[].license.id`, or `licenses[].license.name`.

Bundles check each Syft or CycloneDX file inside them the same way.

```shell
gatecheck syft dir:. -o syft-json=sbom.syft.json -o cyclonedx-json=sbom.cdx.json
gatecheck validate --config gatecheck.yaml sbom.syft.json
gatecheck list sbom.syft.json
```

`gatecheck list` on Syft JSON prints each package with its version, type, and licenses.

## Config

```yaml
license:
  enabled: true
  deny:
    - GPL-*
    - AGPL-*
  allow: []
  denyUnknown: false
  packageRiskAcceptance:
    - name: busybox
    - purl: pkg:apk/alpine/apk-tools
      metadata:
        tags:
          - reviewed 2026-11
```

- `enabled` turns the rules on. With `enabled: false` (the default), Syft JSON and CycloneDX BOMs pass the license rules.
- `deny` lists patterns that fail a license.
- `allow`, when it is not empty, fails every license that matches none of its patterns. Leave it empty to allow everything that is not denied.
- `denyUnknown` fails a package that declares no license, or only `NOASSERTION`, `NONE`, or `UNKNOWN`. With `false`, those packages pass.
- `packageRiskAcceptance` skips the license check for listed packages. An entry with `purl` matches by package URL type, namespace, and name, and by version when the purl has one. Otherwise `name` matches the package name without regard to case.

Patterns are case-insensitive globs. `*` matches any run of characters, and `?` matches one. `GPL-*` matches `GPL-2.0-only` and `GPL-3.0-or-later`. It does not match `LGPL-2.1-only` or a bare `GPL`. A pattern with no wildcard has to equal the license. Free-text names such as `Public Domain` are compared the same way.

## Expressions

Licenses can be SPDX expressions. `AND` binds tighter than `OR`, parentheses group, and the operators are case-insensitive.

- `MIT OR GPL-3.0-only` passes when either side passes, since you can choose MIT.
- `MIT AND GPL-3.0-only` passes only when both sides pass.
- `GPL-2.0-only WITH Classpath-exception-2.0` is checked as the full string and as `GPL-2.0-only`. A deny pattern that matches either one fails it. An `allow` entry that matches the full `WITH` string passes it even when the base license is denied.

A package that lists several licenses has to pass each of them, as if they were joined with `AND`. A string that is not a valid expression, such as `GPL v2 or later`, is checked as one license name.

## Results

Each failing package is logged with its name, version, purl, and the reason, such as `GPL-2.0-only is denied by "GPL-*"`. The report then fails with `validation failure: License: N package(s) failed the license policy`, and `validate` exits 1.

For a CycloneDX BOM, the license rules and the vulnerability rules both run. Both failures are reported.

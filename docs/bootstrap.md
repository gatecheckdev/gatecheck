# Bootstrap

`gatecheck bootstrap` downloads the scanners whose reports gatecheck reads, checks each file, and installs them under a gatecheck data directory.

```shell
gatecheck bootstrap
gatecheck bootstrap --tools grype,syft
gatecheck bootstrap --tools gosec,hadolint,zizmor
gatecheck bootstrap --tools scorecard,trufflehog,cosign
gatecheck bootstrap --list
```

Pinned versions are compiled into gatecheck. The current pins are Grype `0.121.0`, Syft `1.55.0`, Gitleaks `8.30.1`, semgrep `1.182.1`, Trivy `0.76.1`, osv-scanner `2.7.0`, gosec `2.30.0`, hadolint `2.15.1`, zizmor `1.32.0`, OpenSSF Scorecard `5.6.0`, trufflehog `3.99.8`, and cosign `3.1.4`. They live in `internal/bootstrap/versions.go`.

gosec, hadolint, zizmor, scorecard, trufflehog, and cosign are not in the default install. gosec, hadolint, and zizmor each check one kind of source (Go code, Dockerfiles, and GitHub Actions workflows). scorecard rates a repository's supply-chain practices, trufflehog is a second secrets scanner, and cosign verifies signatures. Name them in `--tools` when you want them.

## Directory

Binaries go in `bin` under the gatecheck home.

`GATECHECK_HOME` sets that directory. When it is empty, the location is:

- Linux: `$XDG_DATA_HOME/gatecheck`, or `~/.local/share/gatecheck`.
- macOS: `$XDG_DATA_HOME/gatecheck` when `XDG_DATA_HOME` is set, otherwise `~/Library/Application Support/gatecheck`.
- Windows: `%LOCALAPPDATA%\gatecheck`, then `%APPDATA%\gatecheck`, then the user profile.

A second run that already has the pinned file and its version stamp prints `<tool> <version> already installed` and skips the download. `--force` downloads again. The stamp is written after the binary is in place.

`--list` prints every supported tool, or only the ones named in `--tools`, and does not download. `--force` is ignored while listing. A binary with no stamp shows `unknown`. A missing tool shows `-`.

```
TOOL         PINNED     INSTALLED  PATH
grype        0.121.0    0.121.0    /home/ada/.local/share/gatecheck/bin/grype
syft         1.55.0     -          -
gitleaks     8.30.1     8.30.1     /home/ada/.local/share/gatecheck/bin/gitleaks
semgrep      1.182.1    1.182.1    /home/ada/.local/share/gatecheck/bin/osemgrep
trivy        0.76.1     0.76.1     /home/ada/.local/share/gatecheck/bin/trivy
osv-scanner  2.7.0      2.7.0      /home/ada/.local/share/gatecheck/bin/osv-scanner
gosec        2.30.0     -          -
hadolint     2.15.1     2.15.1     /home/ada/.local/share/gatecheck/bin/hadolint
zizmor       1.32.0     -          -
scorecard    5.6.0      -          -
trufflehog   3.99.8     3.99.8     /home/ada/.local/share/gatecheck/bin/trufflehog
cosign       3.1.4      -          -
```

## Flags

- `--tools`: comma-separated names. The default is `grype,syft,gitleaks,semgrep,trivy,osv-scanner`. `gosec`, `hadolint`, `zizmor`, `scorecard`, `trufflehog`, and `cosign` are also accepted. Names are lowercased. `osemgrep` means `semgrep`. An unknown name is an error: `unknown tool "not-a-scanner" (supported: grype, syft, gitleaks, semgrep, trivy, osv-scanner, gosec, hadolint, zizmor, scorecard, trufflehog, cosign)`.
- `--force`: reinstall even when the pinned version is already present.
- `--list`: print the table above.

`bootstrap` takes no positional arguments.

## Grype, Syft, Gitleaks, Trivy, gosec, scorecard, and trufflehog

Each tool is a GitHub release asset. gatecheck downloads `<name>_<version>_checksums.txt`, looks up the asset's SHA-256, downloads the archive, and checks the digest before extracting the binary. The install is a write to a temporary file in the destination directory, then a rename.

| Tool | Release | Asset name |
| --- | --- | --- |
| Grype | `anchore/grype` | `grype_<version>_<os>_<arch>.tar.gz`, or `.zip` on Windows |
| Syft | `anchore/syft` | `syft_<version>_<os>_<arch>.tar.gz`, or `.zip` on Windows |
| Gitleaks | `gitleaks/gitleaks` | `gitleaks_<version>_<os>_<arch>.tar.gz`, or `.zip` on Windows |
| Trivy | `aquasecurity/trivy` | `trivy_<version>_<OS>-<arch>.tar.gz`, or `.zip` on Windows |
| gosec | `securego/gosec` | `gosec_<version>_<os>_<arch>.tar.gz`, on Windows too |
| scorecard | `ossf/scorecard` | `scorecard_<version>_<os>_<arch>.tar.gz`, on Windows too. The checksum file is `scorecard_checksums.txt`. |
| trufflehog | `trufflesecurity/trufflehog` | `trufflehog_<version>_<os>_<arch>.tar.gz`, on Windows too |

Gitleaks names `amd64` as `x64`, `386` as `x32`, and `arm` as `armv6` or `armv7`.

Trivy uses its own asset names: `Linux-64bit`, `Linux-32bit`, `Linux-ARM` (armv7), `Linux-ARM64`, `Linux-PPC64LE`, `Linux-s390x`, `macOS-64bit`, `macOS-ARM64`, `windows-64bit`, and `FreeBSD-64bit`. The checksum file is `trivy_<version>_checksums.txt`. The archive contains `trivy`, or `trivy.exe` on Windows, plus `README.md`, `LICENSE`, and template files. gatecheck installs only the binary.

Published assets:

- Grype: macOS amd64 and arm64; Linux amd64, arm64, ppc64le, and s390x; Windows amd64.
- Syft: macOS amd64 and arm64; Linux amd64, arm64, ppc64le, riscv64, and s390x; Windows amd64 and arm64.
- Gitleaks: macOS x64 and arm64; Linux x64, x32, arm64, armv6, and armv7; Windows x64, x32, and arm64.
- Trivy: macOS amd64 and arm64; Linux 386, amd64, armv7, arm64, ppc64le, and s390x; Windows amd64; FreeBSD amd64.
- gosec: macOS amd64 and arm64; Linux amd64, arm64, ppc64le, and s390x; Windows amd64 and arm64.
- scorecard and trufflehog: amd64 and arm64 on macOS, Linux, and Windows.

A platform with no asset fails that tool. The message looks like `grype has no published release asset for windows/arm64`. Other requested tools still install. The command exits 2 when any requested tool failed this way, or when a download or checksum check failed.

## osv-scanner

osv-scanner publishes a raw binary, not an archive. gatecheck downloads `osv-scanner_SHA256SUMS` from the `google/osv-scanner` release, checks the asset's SHA-256, marks the file executable, and installs it as `osv-scanner`, or `osv-scanner.exe` on Windows.

Asset names:

- `osv-scanner_linux_amd64` and `osv-scanner_linux_arm64`
- `osv-scanner_darwin_amd64` and `osv-scanner_darwin_arm64`
- `osv-scanner_windows_amd64.exe` and `osv-scanner_windows_arm64.exe`

Those six platforms are the published set. Anything else fails that tool with the same kind of message as a missing Grype asset.

## hadolint

hadolint also publishes a raw binary. gatecheck downloads `checksums.sha256` from the `hadolint/hadolint` release, checks the asset, and installs it as `hadolint`, or `hadolint.exe` on Windows.

Asset names: `hadolint-linux-x86_64`, `hadolint-linux-arm64`, `hadolint-macos-x86_64`, `hadolint-macos-arm64`, and `hadolint-windows-x86_64.exe`. Windows arm64 has no asset.

## cosign

cosign publishes raw binaries. gatecheck downloads `cosign_checksums.txt` from the `sigstore/cosign` release, checks the asset, and installs it as `cosign`, or `cosign.exe` on Windows. Assets: `cosign-darwin-amd64`, `cosign-darwin-arm64`, `cosign-linux-amd64`, `cosign-linux-arm64`, `cosign-linux-arm` (armv7), `cosign-linux-ppc64le`, `cosign-linux-s390x`, `cosign-linux-riscv64`, and `cosign-windows-amd64.exe`.

cosign is a gate on its own: `cosign verify` and `cosign verify-blob` exit non-zero when a signature does not check out, and `gatecheck cosign` passes that status through. Put it in the pipeline before `validate`:

```shell
gatecheck cosign verify-blob --bundle app.tar.gz.sigstore.json \
  --certificate-identity-regexp 'https://github.com/example/app/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com app.tar.gz
gatecheck cosign verify --certificate-identity-regexp 'https://github.com/example/app/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/example/app:1.2.3
```

## zizmor

zizmor publishes archives but no checksum file. The SHA-256 of each `zizmorcore/zizmor` asset for the pinned version is compiled into gatecheck next to the version in `internal/bootstrap/versions.go`. gatecheck checks the download against that digest before extracting `zizmor`, or `zizmor.exe` on Windows. Moving the zizmor pin means updating those digests too.

Asset names: `zizmor-x86_64-unknown-linux-gnu.tar.gz`, `zizmor-aarch64-unknown-linux-gnu.tar.gz`, `zizmor-x86_64-apple-darwin.tar.gz`, `zizmor-aarch64-apple-darwin.tar.gz`, and `zizmor-x86_64-pc-windows-msvc.zip`. zizmor's Linux builds link glibc. Windows arm64 has no asset.

## Semgrep (osemgrep)

Semgrep publishes no GitHub release assets. Bootstrap reads `https://pypi.org/pypi/semgrep/<version>/json`, picks the wheel for this machine, and checks the wheel against the SHA-256 in that JSON.

The wheel contains a native binary at `semgrep-<version>.data/purelib/semgrep/bin/semgrep-core`, and on Linux a `semgrep/bin/libs/` directory of shared libraries. Invoked with argv[0] `osemgrep`, that binary is semgrep's experimental native CLI.

On macOS and Linux, gatecheck installs `semgrep-core` and a symlink named `osemgrep` in the same directory, plus `libs/` beside them. On Windows it installs one copy named `osemgrep.exe`. Success looks like `installed semgrep 1.182.1 /home/ada/.local/share/gatecheck/bin/osemgrep`.

Wheels exist for:

- macOS x86_64 and arm64
- Linux glibc (`manylinux`) and musl (`musllinux`), x86_64 and aarch64
- Windows amd64

On Linux, gatecheck reads the dynamic linker of its own executable. An interpreter path containing `musl` selects the musl wheel. Anything else selects the glibc wheel.

A platform with no wheel is skipped. Standard error says `semgrep: no PyPI wheel for <platform>; osemgrep wheels are published for macOS (x86_64, arm64), Linux glibc and musl (x86_64, aarch64), and Windows amd64`. A wheel that has no `semgrep-core` is also skipped: `semgrep: wheel <filename> does not contain semgrep-core; skipped`. A skip leaves the command successful when every other requested tool succeeded. A bad digest or a failed download is still an error.

`osemgrep scan` is the command that writes Semgrep JSON. `gatecheck semgrep` and `gatecheck osemgrep` add `--experimental` immediately after `scan` when you did not pass it. Other osemgrep commands need that flag from you. `osemgrep --version` tries to execute `pysemgrep` and fails. This works:

```shell
gatecheck semgrep --experimental --version
```

## Running a scanner

```shell
gatecheck grype dir:. -o json > grype-report.json
gatecheck syft dir:. -o cyclonedx-json > cyclonedx-syft.json
gatecheck gitleaks detect --report-format json --report-path gitleaks-report.json
gatecheck semgrep scan -e 'eval($X)' -l python --json t.py > semgrep-report.json
gatecheck trivy fs --format json --output trivy-report.json .
gatecheck osv-scanner scan source --format json . > osv-scanner-report.json
gatecheck gosec -fmt sarif -out gosec.sarif ./...
gatecheck hadolint -f sarif Dockerfile > hadolint.sarif
gatecheck zizmor --format sarif .github/workflows > zizmor.sarif
GITHUB_AUTH_TOKEN=... gatecheck scorecard --repo github.com/example/app --format json > scorecard-report.json
gatecheck trufflehog git file://. --json > trufflehog-report.json
```

scorecard and trufflehog JSON are their own report types, gated with the `scorecard` and `trufflehog` config sections. See [Supported reports](./supported-reports.md).

gosec, hadolint, and zizmor reports are read as SARIF. Gate them with the `sarif` section of the config. See [Supported reports](./supported-reports.md).

Arguments, standard input, standard output, standard error, and the scanner's exit status are passed through. `gatecheck grype --help` is Grype's help. gatecheck does not parse flags after these command names.

The managed binary is used when it is present. Otherwise gatecheck looks on `PATH`: `grype`, `syft`, `gitleaks`, `trivy`, `osv-scanner`, `gosec`, `hadolint`, `zizmor`, `scorecard`, `trufflehog`, or `cosign` for those commands; `semgrep` and then `osemgrep` for `gatecheck semgrep`; `osemgrep` only for `gatecheck osemgrep`. `--experimental` is inserted only when the program that will run is named `osemgrep`. A Python `semgrep` on `PATH` is left unchanged.

When neither copy exists, the command prints one line and exits 2:

```
gatecheck: grype is not installed; run `gatecheck bootstrap`
```

The name in that line is the command you typed.

## What stays outside bootstrap

Coverage files (LCOV, Clover, Cobertura) come from the language toolchain. Bootstrap does not install those tools.

CycloneDX is a report format. Syft writes it with `-o cyclonedx-json`, and Grype can write a CycloneDX vulnerability report. Those are the files `list` and `validate` score. Any other tool's CycloneDX JSON BOM is scored the same way. There is no separate CycloneDX scanner.

Syft's own JSON (`-o syft-json`) is a package list. `list` prints its packages and licenses, and `validate` checks them with the license rules. See [License gating](./licenses.md). Syft also writes CycloneDX, which gets the same license rules plus the vulnerability rules when the BOM has vulnerabilities.

Trivy JSON (`trivy fs --format json`, `trivy image --format json`, and the other Trivy scanners' JSON output) is a report type. The contents identify it. A filename containing `trivy` is the fallback when the contents are ambiguous. A CycloneDX BOM stays CycloneDX even when the name contains `trivy`. Misconfigurations, secrets, and licenses are ignored. Trivy SARIF is a SARIF report.

osv-scanner JSON (`osv-scanner scan source --format json`) is a report type. The contents identify it when `results` holds objects with a `packages` array. A filename containing `osv` is the fallback, so `osv-scanner-report.json` still works when the document is only `{"results":[]}`. Each vulnerability group is one finding. Aliases of that group are not counted again. `max_severity` is a CVSS base score. License-only packages are skipped.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [UNRELEASED]

This release reworks the CLI settings layer and changes exit codes. See Changed. Fixes #73.

### Added

- OpenSSF Scorecard JSON (`scorecard --format json`) is a report type. The `scorecard` config section fails a report whose aggregate score, or a named check's score, is below a minimum. Inconclusive checks are skipped with a warning.
- trufflehog JSON (`--json`, one object per line) is a report type. `trufflehog.limitEnabled` fails on any finding, and `verifiedOnly` counts only verified secrets. `list` never prints secret values.
- `gatecheck bootstrap --tools scorecard,trufflehog,cosign` installs pinned OpenSSF Scorecard 5.6.0, trufflehog 3.99.8, and cosign 3.1.4, and `gatecheck scorecard`, `gatecheck trufflehog`, and `gatecheck cosign` run them. A failed `gatecheck cosign verify` fails the CI step with cosign's status. Fixes #105.

- `--log-level debug|info|warn|error` and `--log-format text|json` on every command, with `GATECHECK_LOG_LEVEL` and `GATECHECK_LOG_FORMAT`. Text logs are colored only on a terminal, and `NO_COLOR` turns color off.
- `validate --format table|markdown|json` prints the result to stdout. `list` and `list-all` take `--format table|markdown|json`. `list-all --format json` is one array keyed by file.
- `validate --input-type`, and `validate` reads stdin when FILE is omitted and `--input-type` is set.
- `validate --epss-url` and `--kev-url`. `list-all --epss-filename` and `--epss-url`.
- `GATECHECK_KEV_FILENAME` sets `--kev-filename`.
- `validate` warns when there is no config, and when the config has keys gatecheck does not read. `config convert` warns about those keys too.

- `gatecheck bootstrap --tools gosec,hadolint,zizmor` installs pinned gosec 2.30.0, hadolint 2.15.1, and zizmor 1.32.0. `gatecheck gosec`, `gatecheck hadolint`, and `gatecheck zizmor` run them. Their SARIF output is gated with the `sarif` config section. They are not part of the default install. zizmor publishes no checksum file, so its asset digests are pinned in gatecheck.
- `gatecheck bootstrap --list` shows every supported tool.
- The `license` config section fails Syft JSON and CycloneDX SBOMs whose package licenses match `deny` patterns, fall outside a non-empty `allow` list, or are missing when `denyUnknown` is set. SPDX `AND`, `OR`, and `WITH` expressions are evaluated. `packageRiskAcceptance` skips packages by purl or name. Fixes #103.
- `list` prints the packages and licenses in Syft JSON, and `validate` and bundles check Syft JSON with the license rules. Both used to return an error.
- `validate --vex FILE`, `GATECHECK_VEX`, and the config's `vex.files` read OpenVEX and CycloneDX VEX documents. Grype, CycloneDX, Trivy, and osv-scanner findings marked `not_affected`, `fixed`, `false_positive`, or `resolved` are skipped before the KEV, EPSS, and severity rules. A statement that names packages matches by package URL. The latest statement wins. Fixes #102.

### Changed

- Exit codes: 2 for usage errors, files that cannot be read or written, and reports, configs, or VEX files that cannot be decoded; 3 when EPSS or KEV data cannot be loaded. These used to be 255. A missing scanner for a passthrough command also exits 2.
- `--audit` only turns a threshold failure into exit 0. Unsupported reports, decode errors, and EPSS or KEV failures now fail in audit mode too.
- `--silent` keeps warnings. It used to show errors only. Use `--log-level error` for the old behavior.
- Coverage thresholds over 1 are read as percents, so `80` means `0.8`, with a warning.
- `config init` and `config convert` indent JSON and YAML by two spaces, and indent TOML tables. JSON config files write `metadata` for CVE entries instead of `Metadata`. Both spellings are read.
- `list-all` exits 2 when a file cannot be read or listed. It still lists the other files first. It loads EPSS data once per run instead of once per file.
- `bundle remove` of a label that is not in the bundle exits 2 and leaves the bundle unchanged.
- Each run builds a new command tree. configkit and Viper are gone. Settings are read flag, then environment variable, then default.

### Fixed

- `GATECHECK_VERBOSE`, `GATECHECK_SILENT`, and `GATECHECK_AUDIT` panicked on any value. They now take booleans, and a bad value is a usage error.
- `--audit=false` lost to `GATECHECK_AUDIT=true`. A flag now wins over its variable.
- The KEV file setting read `GATECHECK_EPSS_FILENAME`, so setting that variable made `validate` read the EPSS CSV as KEV.
- `bundle create` did not truncate an existing file, and `bundle add` and `bundle remove` could leave old bytes after a shorter bundle.
- The Grype KEV rule compared ids with case. It now ignores case and also checks a match's related CVE ids.
- EPSS CSV files with a `+0000` offset in the `score_date` header failed to parse.
- Config files are closed after reading. The EPSS and KEV files passed to `validate` and `list` are closed when the command ends.

## [0.10.0] - 2026-10-30

### Added

- `list` and `validate` read SARIF 2.1.0 from any tool, including KICS, Checkov, Bandit, govulncheck, and `semgrep --sarif`. Severity limits use `security-severity` when it is set, and the SARIF level otherwise. `sarif.ruleLimit` denies rule ids and `sarif.ruleRiskAcceptance` allows them. A SARIF report with no findings prints `No sarif findings`.
- `gatecheck bootstrap` installs pinned Trivy 0.76.1, and `gatecheck trivy` runs it.
- Trivy JSON reports work with `list`, `validate`, and `bundle`. Severity limits and CVE allow and deny lists follow the Grype rules.
- `gatecheck bootstrap` installs pinned osv-scanner 2.7.0, and `gatecheck osv-scanner` runs it.
- osv-scanner JSON reports work with `list`, `validate`, and `bundle`. Severity limits and CVE allow and deny lists follow the Grype rules.

### Changed

- Report type comes from the file contents. The filename is used only when the contents are ambiguous.
- Any CycloneDX JSON BOM with vulnerabilities is listed and validated with the `cyclonedx` rules, whichever tool wrote it. A missing severity word falls back to the CVSS score.
- `gatecheck bootstrap --list` widens the tool column so `osv-scanner` fits.

### Fixed

- A CycloneDX file with `grype` in the name was read as Grype, so its vulnerabilities were ignored. Fixes #80.
- CycloneDX `list` showed the previous row's link for a vulnerability with no advisories. Each row now uses its own advisory URL, then `source.url`, then the first `references[].source.url`, and `-` when there is none. Fixes #81.
- Coverage `list` printed `NaN%` when a report had no records of a kind, such as LCOV without branch records. It now prints `N/A`. `validate` skips that threshold and logs a warning instead of passing it silently. Fixes #82.

## [0.9.0] - 2026-10-23

### Added

- `gatecheck agent-guide` (alias `llm`) prints a markdown guide for coding agents. The text is `docs/agent-guide.md`.
- `gatecheck bootstrap` installs pinned Grype, Syft, Gitleaks, and semgrep's experimental osemgrep CLI. `gatecheck grype`, `syft`, `gitleaks`, `semgrep`, and `osemgrep` run the managed binaries.
- `gatecheck update` (aliases `self-update` and `upgrade`) downloads a GitHub release, checks `checksums.txt`, and replaces the running binary

### Changed

- `list` prints one sentence when a report has no findings, instead of an empty table. The lines are `No grype vulnerabilities`, `No cyclonedx vulnerabilities`, `No semgrep findings`, and `No gitleaks findings`. `--markdown` prints the same line.
- Require Go 1.26, the oldest release still supported upstream. CI tests Go 1.26 and 1.27.
- Add Dependabot for weekly Go module and GitHub Actions updates.
- Cache the current EPSS file and send a gatecheck User-Agent on download

### Fixed

- Table headers are uppercased without splitting words, so Semgrep prints `OWASP IDS`. Footer values such as `50.00%` stay intact.

## [0.8.1] - 2025-04-09

### Fixed

- Updated EPSS schema to work with 3.14.2025

## [0.8.0] - 2024-10-23

* Fixed a bug where validation failures were not resulting in a non-zero exit code
* Renamed the --file / -f CLI argument to --config / -f for consistency with other tools
* improvements to validate output
   These "improvements" are short term hacks. There is a need for a fundamental
   overhaul of how output is generated to improve usability
* Implemented code coverage support.
* Updated the docs to reflect the removal of the --all flag

## [0.7.6] - 2024-09-08

### Fixed

- Crash when running `gatecheck bundle add` with no tags

## [0.7.5] - 2024-06-18

### Fixed

- Missing `slog.Error` for KEV validations
- Use base EPSS url instead of a specific date to get the latest data
- Use a *os.File for kev and epss validation to simplify CLI runtime logic

## [0.7.0] - 2024-05-17

### Changed

- Use ConfigKit with a metaconfig for all commands

### Added

- Gatecheck Config Encoder & Decoder

## [0.6.2] - 2024-05-15

### Changed

- Remove debug information from semgrep decoding

## [0.6.1] - 2024-05-15

### Changed

- Use a table writing package instead of the builtin package

### Added

- `gatecheck list --markdown` support for rendering markdown tables

## [0.6.0] - 2024-04-26

### Changed

- Removed legacy CLI and deprecated pkg code

## [0.5.0] - 2024-04-26

### Fixed

- Semgrep parsing error by switching to any type instead of []string
- Slog validation errors for clarity

## [0.4.1] - 2024-04-02

### Fixed

- EPSS Score URL default date go's std lib date parsing uses '02' for day
- Viper flag collision between list and validate commands
- EPSS URL env var use

## [0.4.0] - 2024-03-19

### Added

- New CLI v1 behind feature flag, in development
- More robust version information
- CLI v1 debug and silent flags for logging
- CLI v1 config init
- CLI v1 config info
- CLI v1 config convert
- CLI v1 bundle
- CLI v1 list
- CLI v1 list all with epss scores

### Fixed

- Wrap msg in bytes with string for logging
- Grype & Cyclonedx validation errors

### Changed

- Old CLI files moved to cmd/v0
- Deprecated existing CLI
- package organization
- rules execution order is more structured

## [0.3.0] - 2023-10-17

### Deprecated

- Defect Dojo export will be deprecated in the future in favor of just using the API, notice added

### Added

- New Environment Variables for Defect Dojo

### Changed

- Defect Dojo exporting to include mandatory values
- Time Zone fix with exporting

## [0.2.2] - 2023-10-3

### Changed

- Added additional logging for defect dojo export

### Fixed

- Removed lazy reader in favor of fileOrEmptyBuf for better error handling
- Verbose flag bug where the CLI would always be log level debug instead of warn
- Grype decoder checkReport will use descriptor Timestamp instead of name since name is not a required field

## [0.2.1] - 2023-09-12

### Changed

- Update to go 1.21.1 to avoid packaging errors

## [0.2.0] - 2023-09-05

### Changed

- Update to go 1.21
- Custom logger implementation using zerolog to std lib slog
- Release process documentation

### Added

- EnableSimpleRiskAcceptance Products API settings option
- DeduplicationOnEngagement Engagements API settings option
- CloseOldFindings Import-Scan API settings option
- CloseOldFindingsProductScope Import-Scan API settings option
- CreateFindingGroupsForAllFindings Import-Scan API settings option
- Documentation for exported functions and structs

### Fixed

- Bug where Gitleaks report with no secrets aren't properly decoded
- A bunch of golangci-lint complaints

### Changed

- Update DefectDojo Export Service calls and unit-tests
- Update README documentation

## [0.1.3] - 2023-08-04

### Fixed

- Bug with EPSS Time Zone (may need further discovery down the line)
- LazyReader Export bug (AWS API wants to seek on the body which doesn't work on the LazyReader)

## [0.1.2] - 2023-08-02

### Changed

- Updated dependencies
- Bug fix, EPSS to use current UTC time
- Bug fix, validation command has a seperate bundle function to prevent error overwriting on recursive calls

### Added

- Lazy File Reader in internal/io to open file errors at read

## [0.1.0] - 2023-07-26

### Changed

- _Major Refactoring_
- Bundling is now a gzipped tarball with a manifest file
- Using "Agents" for KEV and EPSS downloading, simplify interface
- Encoding package refactor, using generics
- Common validation pattern between artifacts
- Report artifacts as isolated packages instead
- Table refactor for simplified table formatting
- Table sorting pattern updated
- Table printing to use unicode pretty borders
- Fully refactored the validation pattern

### Added

- EPSS Allow and Deny Thresholds
- Validation rules via functions that can be layered

### Removed

- Config object in favor of using a map[string]any which makes it easier to support new reports in the future
- Encoding package that relied decodeBytes functions

## [0.0.10] - 2023-06-07

### Changed

- New ASCII Logo
- Bundle logging to use internal logger
- Sort Grype print by Severity, then by Package
- EPSS Service will write to existing CVE slice instead of querying
- Simplified EPSS API Queries with a better async strategy
- Added Data Store that can query an imported CSV file for EPSS Scores
- Added a download command that will pull the CSV file from the API
- Semgrep table ordering and prefix clipping
- "CleanAndAbreviate" rename to ClipLeft or ClipRight

### Added

- Version Command with Logo Output
- Basic Logging Capabilities with custom logger, (Zerolog abstraction) package in internal/log
- Global Verbose flag and elapsed execution time tracking
- Debugs in CLI commands
- Make commands for test and coverage
- Allow Deny List for Grype reports
- 'allow-missing' flag to bundle command
- Sort tables by single or multiple columns in ascending, descending or custom order
- Export to AWS S3
- Support CycloneDX BOM and Vulnerabilities in Print, Bundle, Export, and Validate
- Some debug logs focused on measuring performance
- bundle extract command

## [0.0.9] - 2023-02-06

### Added

- Additional debug information for bad status codes on export

### Changed

- Marked config flag in validate command as required
- Upgrade to go 1.20, no functional updates or changes to code

### Fixed

- Bug in dojo export causing the open file to be read twice resulting in a blank file upload

## [0.0.8] - 2023-01-24

### Added

- Defect Dojo Export has a exponential backoff between queries
- Gatecheck Bundle
- Validation in Bundle
- Predictive encoding to avoid the need to label each file type
- KEV Blacklisting
- EPSS Table
- Strings package for pretty table printing

### Changed

- Exporter interface to allow retries on failed exports
- Validation strategy
- Removed implementation side interfacing for export services and epss in favor of caller side interfacing
- Main function moved to cmd/gatecheck for better package conformation

### Removed

- Gatecheck Report in favor of Gatecheck Bundle
- The concept of Assets, treating everything as artifacts
- Unnecessary complexity in Defect Dojo Export Service

## [0.0.7] - 2022-11-9

### Added

- Gitleaks support, has the config option to allow secrets
- Gitleaks test report generated from Juice Shop v14.3.0-4-g2c757a928
- Gitleaks to CLI
- Gitleaks as Export target to Defect Dojo
- Blacklist Validation using KEVs from CISA
- Dates to change log releases
- CI/CD GitHub actions to auto release on tag

### Changed

- YAML 2.0 to 3.0 in all places
- TODO: Retry option for export command at CLI level
- Use pointers for pkg/artifact values to allow nil
- Use pointers for pkg/config values to allow nil
- Unit tests to prevent nil pointer issues
- Silence Usage text on error
- Use std err in main for proper highlighting

## [0.0.6]

### Added

- Semgrep add to report command and unit tests

## [0.0.5]

### Changed

- Use json and yaml decoders and encoders instead of wrapping with the reader, writer pattern
- Unit tests
- fields/CVE to finding for use in other modules
- Deprecated 'WithAsset' on Grype
- Added 'WithScanReport' to Artifacts
- Refactored the cmd to use the new IO functions
- Refactor unit tests in cmd package to be more uniform
- Removed test utility and internal packages in favor of IO functions
- Move config, report, and validator to pkg/gatecheck for simplified folder structure
- Moved validate responsibility to the artifact
- Converted ExportGrype in exporter to just Export using a scan type enum for better support for multiple file types

### Added

- JSON struct tags to config for additional support
- Entity Documentation to README
- Semgrep Artifact
- Semgrep Entity
- Generic Asset wrapper for files
- cmd package now has a IO file to consolidate common operations
- Semgrep command to CLI

## [0.0.4]

### Fixed

- A new report command takes the project name from the config file

## [0.0.3]

### Removed

- Debug prints in report command
- Use of ioutil which was deprecated

### Changed

- Handle edge case of timezone not being able to load due to lack of tzdata pkg/exporter/defectDojo/exporter

## [0.0.2]

### Removed

- init function from all commands to prevent unexpected behaviors during test

### Changed

- Commands have a wrapper function to inject arguments
- Internal/Util test package uses a ReadCloser interface
- Updated cmd unit tests to use ReadCloser to open test files

### Added

- Exporter pkg
- Defect Dojo Exporter pkg
- Export command to CLI
- Environment variables for Defect Dojo exporter
- GitHub Action for testing

## [0.0.1] - 2022-06-28

### Added

- Artifact pkg
- Config pkg
- Report pkg
- internal utility file system functions
- Initial CLI functions using Cobra
- Validator for Grype

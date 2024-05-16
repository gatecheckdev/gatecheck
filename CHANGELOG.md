# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

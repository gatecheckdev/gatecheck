# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [UNRELEASED]
### Added
- Additional debug information for bad status codes on export

### Changed
- Marked config flag in validate command as required

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
 
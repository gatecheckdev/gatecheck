# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [UNRELEASED]
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
 
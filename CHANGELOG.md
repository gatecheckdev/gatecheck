# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [UNRELEASED]
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

## [0.0.1] - 2022-06-28
### Added
- Artifact pkg
- Config pkg
- Report pkg
- internal utility file system functions
- Initial CLI functions using Cobra
- Validator for Grype
 
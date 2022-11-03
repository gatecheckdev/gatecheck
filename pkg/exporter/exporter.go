package exporter

import (
	"io"
)

type Exporter interface {
	Export(reportFile io.Reader, scanType ScanType) error
}

type ScanType string

// Source for Scan Type Values https://demo.defectdojo.org/api/v2/doc/
const (
	Grype    ScanType = "Anchore Grype"
	Semgrep           = "Semgrep JSON Report"
	Gitleaks          = "Gitleaks Scan"
)

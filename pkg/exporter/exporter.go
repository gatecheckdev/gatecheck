package exporter

import (
	"io"
)

type Exporter interface {
	Export(reportFile io.Reader, scanType ScanType) error
}

type ScanType string

const (
	Grype ScanType = "Anchore Grype"
)

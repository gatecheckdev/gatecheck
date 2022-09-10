package exporter

import "github.com/gatecheckdev/gatecheck/pkg/artifact/grype"

type Exporter interface {
	ExportGrype(report *grype.ScanReport) error
}

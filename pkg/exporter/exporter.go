package exporter

import (
	"io"
)

type Exporter interface {
	ExportGrype(reportFile io.Reader) error
}

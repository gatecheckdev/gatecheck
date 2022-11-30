package artifact

import (
	"bytes"
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
	"io"
	"time"
)

type ReportType string

const (
	Gitleaks    ReportType = "Gitleaks"
	Grype       ReportType = "Grype"
	Semgrep     ReportType = "Semgrep"
	Unsupported ReportType = "Unsupported"
)

var Timeout = time.Second * 4

// DetectedReportType will return the file type of the data on the reader
func DetectedReportType(r io.Reader) ReportType {

	// Create a Channel to capture results
	decodeFuncs := []func(reader io.Reader) ReportType{
		detectGitleaks,
		detectSemgrep,
		detectGrype,
	}

	c := make(chan ReportType, len(decodeFuncs))

	// Copy the content from the reader into a blank buffer
	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, r)
	if err != nil {
		return Unsupported
	}
	someBytes := buf.Bytes()

	// Trigger go routines for each identifier function
	for _, v := range decodeFuncs {
		go func(decodeFunc func(reader io.Reader) ReportType) {
			c <- decodeFunc(bytes.NewBuffer(someBytes))
		}(v)
	}

	// TIMEOUT Function
	go func() {
		time.Sleep(Timeout)
		close(c)
	}()

	// Use the value from the first function to return a non-unsupported report type first
	for value := range c {
		if value != Unsupported {
			return value
		}
	}
	
	return Unsupported
}

func detectGitleaks(r io.Reader) ReportType {
	var gitleaksScan entity.GitLeaksScanReport
	buf := new(bytes.Buffer)

	if _, err := io.Copy(buf, r); err != nil {
		return Unsupported
	}

	// Gitleaks with no findings will be '[]'
	if buf.String() == "[]" {
		return Gitleaks
	}

	_ = json.NewDecoder(buf).Decode(&gitleaksScan)

	if len(gitleaksScan) >= 1 {
		return Gitleaks
	}

	return Unsupported
}

func detectSemgrep(r io.Reader) ReportType {
	var semgrepScan entity.SemgrepScanReport

	_ = json.NewDecoder(r).Decode(&semgrepScan)

	if semgrepScan.Version != "" {
		return Semgrep
	}

	return Unsupported
}

func detectGrype(r io.Reader) ReportType {

	var grypeScan entity.GrypeScanReport

	_ = json.NewDecoder(r).Decode(&grypeScan)

	if grypeScan.Source != nil {
		return Grype
	}

	return Unsupported
}

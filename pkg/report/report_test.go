package report_test

import (
	"bytes"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"github.com/gatecheckdev/gatecheck/pkg/report"
	"os"
	"testing"
)

var TestGrypeReport = "../../test/grype-report.json"

func TestWriterReader(t *testing.T) {
	buf := new(bytes.Buffer)
	rep := report.NewReport("Test Gate Check Report")
	_ = report.NewWriter(buf).WriteReport(rep)

	rep2, err := report.NewReader(buf).ReadReport()

	if err != nil {
		t.Fatal(err)
	}

	if rep2.ProjectName != "Test Gate Check Report" {
		t.Fatal("Something went wrong")
	}
}

func TestNewReport(t *testing.T) {
	rep := report.NewReport("Test Gate Check Report")

	scanFile, _ := os.Open(TestGrypeReport)

	scan, err := grype.NewScanReportReader(scanFile).ReadScan()
	if err != nil {
		t.Fatal(err)
	}

	grypeAsset := grype.NewAsset("grype-report.json").WithScan(scan)

	rep.Artifacts.Grype = *grype.NewArtifact().
		WithConfig(grype.NewConfig(-1)).
		WithAsset(grypeAsset)

	if err := report.NewWriter(os.Stdout).WriteReport(rep); err != nil {
		t.Fatal(err)
	}
}

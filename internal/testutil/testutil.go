package testutil

import (
	"io"
	"os"
	"path"
	"testing"
)

func ConfigTestCopy(t *testing.T, configFile io.ReadCloser) string {
	// Create temp copy of the config

	tempConfigFilename := path.Join(t.TempDir(), "gatecheck.yaml")
	tempConfigFile, _ := os.Create(tempConfigFilename)

	if _, err := io.Copy(tempConfigFile, configFile); err != nil {
		t.Fatal(err)
	}
	if err := tempConfigFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := configFile.Close(); err != nil {
		t.Fatal(err)
	}

	return tempConfigFilename
}

func GrypeTestCopy(t *testing.T, grypeFile io.ReadCloser) string {
	// Create a temp copy of the grype report

	tempGrypeFilename := path.Join(t.TempDir(), "grype-report.json")
	tempGrypeFile, _ := os.Create(tempGrypeFilename)

	if _, err := io.Copy(tempGrypeFile, grypeFile); err != nil {
		t.Fatal(err)
	}
	if err := tempGrypeFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := grypeFile.Close(); err != nil {
		t.Fatal(err)
	}

	return tempGrypeFilename

}

func ReportTestCopy(t *testing.T, reportFile io.ReadCloser) string {
	// Create a temp copy of the grype report

	tempReportFilename := path.Join(t.TempDir(), "gatecheck-report.json")
	tempReportFile, _ := os.Create(tempReportFilename)

	if _, err := io.Copy(tempReportFile, reportFile); err != nil {
		t.Fatal(err)
	}
	if err := tempReportFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reportFile.Close(); err != nil {
		t.Fatal(err)
	}

	return tempReportFilename
}

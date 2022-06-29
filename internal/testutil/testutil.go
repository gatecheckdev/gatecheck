package testutil

import (
	"io"
	"os"
	"path"
	"testing"
)

func ConfigTestCopy(t *testing.T) string {
	// Create temp copy of the config
	configFilename := os.Getenv("GATECHECK_TEST_CONFIG")
	configFile, _ := os.Open(configFilename)

	tempConfigFilename := path.Join(t.TempDir(), "gatecheck.yaml")
	tempConfigFile, _ := os.Create(tempConfigFilename)

	if _, err := io.Copy(tempConfigFile, configFile); err != nil {
		t.Fatal(err)
	}
	_ = tempConfigFile.Close()
	_ = configFile.Close()

	return tempConfigFilename
}

func GrypeTestCopy(t *testing.T) string {
	// Create a temp copy of the grype report
	grypeFilename := os.Getenv("GATECHECK_TEST_GRYPE")
	grypeFile, _ := os.Open(grypeFilename)
	tempGrypeFilename := path.Join(t.TempDir(), "grype-report.json")

	tempGrypeFile, _ := os.Create(tempGrypeFilename)
	if _, err := io.Copy(tempGrypeFile, grypeFile); err != nil {
		t.Fatal(err)
	}
	_ = tempGrypeFile.Close()
	_ = grypeFile.Close()

	return tempGrypeFilename

}

func ReportTestCopy(t *testing.T) string {
	// Create a temp copy of the grype report
	reportFilename := os.Getenv("GATECHECK_TEST_REPORT")
	reportFile, err := os.Open(reportFilename)
	if err != nil {
		t.Fatal(err)
	}
	tempReportFilename := path.Join(t.TempDir(), "gatecheck-report.json")

	tempReportFile, _ := os.Create(tempReportFilename)
	if _, err := io.Copy(tempReportFile, reportFile); err != nil {
		t.Fatal(err)
	}
	_ = tempReportFile.Close()
	_ = reportFile.Close()

	return tempReportFilename
}

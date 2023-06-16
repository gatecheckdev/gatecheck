package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
)

func TestNewEPSSCmd(t *testing.T) {

	t.Run("test-download-csv-success", func(t *testing.T) {
		config := CLIConfig{EPSSDownloadAgent: strings.NewReader("mock epss file")}
		commandString := fmt.Sprintf("epss download")
		output, err := Execute(commandString, config)

		if err != nil {
			t.Fatal(err)
		}

		t.Log(output)
	})

	t.Run("download-csv-fail", func(t *testing.T) {
		config := CLIConfig{EPSSDownloadAgent: &badReader{}}
		commandString := fmt.Sprintf("epss download")
		_, err := Execute(commandString, config)

		if err == nil {
			t.Fatal("Expected error for bad reader")
		}

	})

	t.Run("success-from-file", func(t *testing.T) {

		config := CLIConfig{EPSSDownloadAgent: new(bytes.Buffer)}
		commandString := fmt.Sprintf("epss -e %s %s", epssTestCSV, grypeTestReport)

		output, err := Execute(commandString, config)

		if err != nil {
			t.Fatal(err)
		}

		t.Log(output)
	})

	t.Run("service-get-error", func(t *testing.T) {
		var sb strings.Builder
		_, _ = sb.WriteString("#model_version:v2023.03.01,score_date:2023-07-14T00:00:00+0000\n")
		_, _ = sb.WriteString("cve,epss,percentile\n")
		_, _ = sb.WriteString("cve-1,badvalue,0.00021\n")

		grypeReport := &grype.ScanReport{}
		grypeReport.Descriptor.Name = "grype"
		grypeReport.Matches = append(grypeReport.Matches,
			models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}})

		grypeFilename := path.Join(t.TempDir(), "grype-report.json")
		_ = json.NewEncoder(MustCreate(grypeFilename, t)).Encode(grypeReport)

		config := CLIConfig{EPSSDownloadAgent: strings.NewReader(sb.String())}
		commandString := fmt.Sprintf("epss --fetch %s", grypeFilename)

		output, err := Execute(commandString, config)
		t.Log(err)
		if err == nil {
			t.FailNow()
		}

		t.Log(output)
	})

	t.Run("success-from-api", func(t *testing.T) {

		match := models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}}
		tempGrypeScanFile := MockAppendedGrypeReport(t, match)

		commandString := fmt.Sprintf("epss --fetch %s", tempGrypeScanFile)
		// This skips the gunzip by passing the file directly
		config := CLIConfig{EPSSDownloadAgent: MustOpen(epssTestCSV, t)}

		output, err := Execute(commandString, config)

		if err != nil {
			t.Fatal(err)
		}

		t.Log(output)
	})

	regularConfig := CLIConfig{EPSSDownloadAgent: MustOpen(epssTestCSV, t)}

	t.Run("bad-file", func(t *testing.T) {
		// Bad Grype file
		commandString := fmt.Sprintf("epss -e %s %s", epssTestCSV, fileWithBadPermissions(t))
		output, err := Execute(commandString, regularConfig)
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
		t.Log(output)

		// Bad EPSS File
		commandString = fmt.Sprintf("epss -e %s %s", fileWithBadPermissions(t), grypeTestReport)
		output, err = Execute(commandString, regularConfig)
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
		t.Log(output)
	})

	t.Run("bad-file-decode", func(t *testing.T) {
		// bad Grype File encoding
		commandString := fmt.Sprintf("epss -e %s %s", epssTestCSV, fileWithBadJSON(t))
		output, err := Execute(commandString, regularConfig)
		if err == nil {
			t.Fatalf("want: error for bad Grype file encoding got: %v", err)
		}
		t.Log(output)

		// bad EPSS File encoding
		commandString = fmt.Sprintf("epss -e %s %s", fileWithBadJSON(t), grypeTestReport)
		output, err = Execute(commandString, regularConfig)
		if err == nil {
			t.Fatalf("want: error for bad EPSS file encoding got: %v", err)
		}
		t.Log(output)
	})

	t.Run("missing-epss-in-datastore", func(t *testing.T) {

		match := models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}}
		tempGrypeScanFile := MockAppendedGrypeReport(t, match)

		commandString := fmt.Sprintf("epss -e %s %s", epssTestCSV, tempGrypeScanFile)

		output, err := Execute(commandString, regularConfig)

		if err != nil {
			t.Log(err)
		}

		t.Log(output)
	})

	t.Run("no-csv-no-service", func(t *testing.T) {

		commandString := fmt.Sprintf("epss %s", grypeTestReport)
		_, err := Execute(commandString, regularConfig)
		t.Log(err)
		if !errors.Is(err, ErrorUserInput) {
			t.Fatalf("want: %v got: %v", ErrorUserInput, err)
		}
	})

}

func MockGrypeReport(t *testing.T, scan grype.ScanReport) string {

	tempGrypeScanFile := path.Join(t.TempDir(), "mock-grype-scan.json")

	f, _ := os.Create(tempGrypeScanFile)
	_ = json.NewEncoder(f).Encode(&scan)

	return tempGrypeScanFile
}

func MockAppendedGrypeReport(t *testing.T, match models.Match) string {
	var grypeScan grype.ScanReport

	_ = json.NewDecoder(MustOpen(grypeTestReport, t)).Decode(&grypeScan)

	grypeScan.Matches = append(grypeScan.Matches, match)

	tempGrypeScanFile := path.Join(t.TempDir(), "mock-grype-scan.json")
	f, _ := os.Create(tempGrypeScanFile)
	_ = json.NewEncoder(f).Encode(grypeScan)

	return tempGrypeScanFile
}

type badReader struct{}

func (r *badReader) Read(_ []byte) (int, error) {
	return 0, errors.New("mock error")
}

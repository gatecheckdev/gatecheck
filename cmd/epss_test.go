package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
)

func TestNewEPSSCmd(t *testing.T) {
	t.Run("success-from-datastore", func(t *testing.T) {

		commandString := fmt.Sprintf("epss %s -f %s", grypeTestReport, epssTestCSV)

		config := CLIConfig{}

		output, err := Execute(commandString, config)

		if err != nil {
			t.Fatal(err)
		}

		t.Log(output)
	})

	t.Run("success", func(t *testing.T) {

		match := models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}}
		tempGrypeScanFile := MockAppendedGrypeReport(t, match)

		commandString := fmt.Sprintf("epss %s", tempGrypeScanFile)
		config := CLIConfig{EPSSService: mockEPSSService{returnError: nil, returnData: []epss.Data{
			{CVE: "A", EPSS: "B", Percentile: "32", Date: "may 3, 2023", Severity: "Critical", URL: "github.com"},
		}}}

		output, err := Execute(commandString, config)

		if err != nil {
			t.Fatal(err)
		}

		t.Log(output)
	})

	t.Run("bad-file", func(t *testing.T) {
		// Bad Grype file
		commandString := fmt.Sprintf("epss %s", fileWithBadPermissions(t))
		output, err := Execute(commandString, CLIConfig{EPSSService: mockEPSSService{}})
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
		t.Log(output)

		// Bad EPSS File
		commandString = fmt.Sprintf("epss %s -f %s", grypeTestReport, fileWithBadPermissions(t))
		output, err = Execute(commandString, CLIConfig{EPSSService: mockEPSSService{}})
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
		t.Log(output)
	})

	t.Run("bad-file-decode", func(t *testing.T) {
		// bad Grype File encoding
		commandString := fmt.Sprintf("epss %s", fileWithBadJSON(t))
		output, err := Execute(commandString, CLIConfig{EPSSService: mockEPSSService{}})
		if !errors.Is(err, ErrorEncoding) {
			t.Fatal(err)
		}
		t.Log(output)

		// bad EPSS File encoding
		commandString = fmt.Sprintf("epss %s -f %s", grypeTestReport, fileWithBadJSON(t))
		output, err = Execute(commandString, CLIConfig{EPSSService: mockEPSSService{}})
		if !errors.Is(err, epss.ErrDecode) {
			t.Fatal(err)
		}
		t.Log(output)
	})

	t.Run("bad-api", func(t *testing.T) {

		match := models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}}
		tempGrypeScanFile := MockAppendedGrypeReport(t, match)

		commandString := fmt.Sprintf("epss %s", tempGrypeScanFile)
		config := CLIConfig{EPSSService: mockEPSSService{returnError: errors.New("mock error")}}
		output, err := Execute(commandString, config)

		if errors.Is(err, ErrorAPI) != true {
			t.Fatal(err)
		}

		t.Log(output)
	})

	t.Run("missing-epss-in-datastore", func(t *testing.T) {

		match := models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}}
		tempGrypeScanFile := MockAppendedGrypeReport(t, match)

		commandString := fmt.Sprintf("epss %s -f %s", tempGrypeScanFile, epssTestCSV)

		output, err := Execute(commandString, CLIConfig{})

		if !errors.Is(err, epss.ErrNotFound) {
			t.Fatalf("Expected not found error, got: %v", err)
		}

		t.Log(output)
	})
}

func MockGrypeReport(t *testing.T, scan artifact.GrypeScanReport) string {

	tempGrypeScanFile := path.Join(t.TempDir(), "mock-grype-scan.json")

	f, _ := os.Create(tempGrypeScanFile)
	_ = json.NewEncoder(f).Encode(&scan)

	return tempGrypeScanFile
}

func MockAppendedGrypeReport(t *testing.T, match models.Match) string {
	var grypeScan artifact.GrypeScanReport

	_ = json.NewDecoder(MustOpen(grypeTestReport, t.Fatal)).Decode(&grypeScan)

	grypeScan.Matches = append(grypeScan.Matches, match)

	tempGrypeScanFile := path.Join(t.TempDir(), "mock-grype-scan.json")
	f, _ := os.Create(tempGrypeScanFile)
	_ = json.NewEncoder(f).Encode(grypeScan)

	return tempGrypeScanFile
}

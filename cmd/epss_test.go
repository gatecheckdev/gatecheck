package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"testing"
	"time"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
)

func TestNewEPSSCmd(t *testing.T) {

	t.Run("test-download-csv-success", func(t *testing.T) {
		config := CLIConfig{EPSSService: newMockEPSSService(nil, 100_000)}
		commandString := fmt.Sprintf("epss download")
		output, err := Execute(commandString, config)

		if err != nil {
			t.Fatal(err)
		}

		t.Log(output)
	})

	t.Run("download-csv-fail", func(t *testing.T) {
		config := CLIConfig{EPSSService: newMockEPSSService(epss.ErrAPIPartialFail, 0)}
		commandString := fmt.Sprintf("epss download")
		_, err := Execute(commandString, config)

		if !errors.Is(err, ErrorAPI) {
			t.Fatal(err, "Expected API failure")
		}

	})

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
		config := CLIConfig{EPSSService: newMockEPSSService(nil, 100).withModFunction(func(c []epss.CVE) {
			c[0] = epss.CVE{ID: "A", Probability: .01934, Percentile: .03294, ScoreDate: time.Now(), Severity: "Critical", Link: "github.com"}
		})}

		output, err := Execute(commandString, config)

		if err != nil {
			t.Fatal(err)
		}

		t.Log(output)
	})

	regularConfig := CLIConfig{EPSSService: newMockEPSSService(nil, 100)}

	t.Run("bad-file", func(t *testing.T) {
		// Bad Grype file
		commandString := fmt.Sprintf("epss %s", fileWithBadPermissions(t))
		output, err := Execute(commandString, regularConfig) 
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
		t.Log(output)

		// Bad EPSS File
		commandString = fmt.Sprintf("epss %s -f %s", grypeTestReport, fileWithBadPermissions(t))
		output, err = Execute(commandString, regularConfig)
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
		t.Log(output)
	})

	t.Run("bad-file-decode", func(t *testing.T) {
		// bad Grype File encoding
		commandString := fmt.Sprintf("epss %s", fileWithBadJSON(t))
		output, err := Execute(commandString, regularConfig)
		if !errors.Is(err, ErrorEncoding) {
			t.Fatal(err)
		}
		t.Log(output)

		// bad EPSS File encoding
		commandString = fmt.Sprintf("epss %s -f %s", grypeTestReport, fileWithBadJSON(t))
		output, err = Execute(commandString, regularConfig)
		if !errors.Is(err, ErrorAPI) {
			t.Fatal(err)
		}
		t.Log(output)
	})

	t.Run("bad-api", func(t *testing.T) {

		match := models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}}
		tempGrypeScanFile := MockAppendedGrypeReport(t, match)

		commandString := fmt.Sprintf("epss %s", tempGrypeScanFile)
		config := CLIConfig{EPSSService: newMockEPSSService(errors.New("mock"), 0)}
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

		if !errors.Is(err, nil) {
			t.Fatalf("Expected not found nil, got: %v", err)
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

type mockEPSSService struct {
	returnError error
	returnN     int64
	modFunc     func([]epss.CVE)
}

func newMockEPSSService(returnError error, returnN int64) mockEPSSService {
	return mockEPSSService{returnError: returnError, returnN: returnN, modFunc: func(c []epss.CVE) {}}
}

func (m mockEPSSService) withModFunction(modFunc func([]epss.CVE)) mockEPSSService {
	m.modFunc = modFunc
	return m
}

func (m mockEPSSService) WriteEPSS(input []epss.CVE) error {
	m.modFunc(input)
	return m.returnError
}

func (m mockEPSSService) WriteCSV(w io.Writer, url string) (int64, error) {
	return m.returnN, m.returnError
}

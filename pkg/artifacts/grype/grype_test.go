package grype

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"gopkg.in/yaml.v3"
)

const GrypeTestReport string = "../../../test/grype-report.json"

func TestEncoding_success(t *testing.T) {
	obj, err := NewReportDecoder().DecodeFrom(MustOpen(GrypeTestReport, t))
	if err != nil {
		t.Fatal(err)
	}
	grypeReport, ok := obj.(*ScanReport)
	if !ok {
		t.Fatalf("want: *ScanReport got: %T", obj)
	}
	if len(grypeReport.Matches) < 10 {
		t.Fatalf("want: <10 got: %d", len(grypeReport.Matches))
	}

	t.Log("\n" + grypeReport.String())
	if !strings.Contains(grypeReport.String(), "curl") {
		t.Fatal("'curl' should exist in string")
	}
}

func TestValidation_success(t *testing.T) {
	grypeFile := MustOpen(GrypeTestReport, t)
	configMap := map[string]Config{ConfigFieldName: {
		Critical: 0,
		High:     0,
	}}

	encodedConfig := new(bytes.Buffer)
	_ = yaml.NewEncoder(encodedConfig).Encode(configMap)
	t.Log(encodedConfig.String())

	err := NewValidator().ValidateFrom(grypeFile, encodedConfig)
	if !errors.Is(err, gcv.ErrValidation) {
		t.Fatalf("want: %v got: %v", gcv.ErrValidation, err)
	}
}

func TestCheckReport(t *testing.T) {
	if err := checkReport(nil); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}
	if err := checkReport(&ScanReport{}); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}

}

func TestValidateFunc(t *testing.T) {
	reportOne := ScanReport{}
	reportOne.Matches = append(reportOne.Matches, models.Match{Vulnerability: models.Vulnerability{
		VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "abc-123", Severity: "Critical"},
	}})

	testTable := []struct {
		label   string
		report  ScanReport
		config  Config
		wantErr error
	}{
		{label: "no-matches", report: ScanReport{}, config: Config{}, wantErr: nil},
		{label: "critical-found-allowed", report: reportOne, config: Config{Critical: -1}, wantErr: nil},
		{label: "critical-found-not-allowed", report: reportOne, config: Config{Critical: 0}, wantErr: gcv.ErrValidation},
		{label: "critical-found-allowed-denylist", report: reportOne,
			config: Config{Critical: -1, DenyList: []ListItem{{Id: "abc-123", Reason: "mock reason"}}}, wantErr: gcv.ErrValidation},
		{label: "critical-found-not-allowed-allowlist", report: reportOne,
			config: Config{Critical: 0, AllowList: []ListItem{{Id: "abc-123", Reason: "mock reason"}}}, wantErr: nil},
	}

	for _, testCase := range testTable {
		t.Run(testCase.label, func(t *testing.T) {
			if err := validateFunc(testCase.report, testCase.config); !errors.Is(err, testCase.wantErr) {
				t.Fatalf("want: %v got: %v", testCase.wantErr, err)
			}
		})
	}
}

func TestScanReport_Remove(t *testing.T) {
	report := ScanReport{}
	report.Matches = []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-2", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-3", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-4", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-5", Severity: "Critical"}}},
	}

	report.RemoveMatches(ByIDs("cve-2", "cve-4"))
	if len(report.Matches) != 3 {
		t.Fatalf("want: match count 3 got: %d", len(report.Matches))
	}
}

func MustReadFile(filename string, fatalFunc func(args ...any)) []byte {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		fatalFunc(err)
	}
	return fileBytes
}

func MustOpen(filename string, t *testing.T) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("test setup failure: %v", err)
	}
	return f
}

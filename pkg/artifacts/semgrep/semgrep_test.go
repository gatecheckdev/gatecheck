package semgrep

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	gosemgrep "github.com/BacchusJackson/go-semgrep"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"gopkg.in/yaml.v2"
)

const TestReport string = "../../../test/semgrep-sast-report.json"

func TestEncoding_success(t *testing.T) {
	obj, err := NewReportDecoder().DecodeFrom(MustOpen(TestReport, t))
	if err != nil {
		t.Fatal(err)
	}
	report, ok := obj.(*ScanReport)
	if !ok {
		t.Fatalf("want: *ScanReport got: %T", obj)
	}
	if len(report.Errors) < 2 {
		t.Fatalf("want: <2 got: %d", len(report.Errors))
	}

	t.Log(report.String())
	if !strings.Contains(report.String(), "WARNING") {
		t.Fatal("'WARNING' should exist in string")
	}
}

func TestValidation_success(t *testing.T) {
	grypeFile := MustOpen(TestReport, t)
	configMap := map[string]Config{ConfigFieldName: {
		Error:   0,
		Warning: 0,
	}}

	encodedConfig := new(bytes.Buffer)
	_ = yaml.NewEncoder(encodedConfig).Encode(configMap)

	err := NewValidator().ValidateFrom(grypeFile, encodedConfig)
	if !errors.Is(err, gcv.ErrValidation) {
		t.Fatalf("want: %v got: %v", gcv.ErrValidation, err)
	}
}

func TestStringClipping(t *testing.T) {
	report := ScanReport{}
	report.Results = append(report.Results, gosemgrep.CliMatch{Path: "./somefile", Start: gosemgrep.Position{Line: 1}, Extra: gosemgrep.CliMatchExtra{Severity: "WARNING"}})
	t.Log(report.String())
}

func TestCheckReport(t *testing.T) {
	if err := checkReport(nil); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}
	if err := checkReport(&ScanReport{}); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}
	if err := checkReport(&ScanReport{Results: make([]gosemgrep.CliMatch, 0)}); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}
	if err := checkReport(&ScanReport{Results: make([]gosemgrep.CliMatch, 0), Errors: []gosemgrep.CliError{}}); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}
	if err := checkReport(&ScanReport{Results: make([]gosemgrep.CliMatch, 0), Errors: make([]gosemgrep.CliError, 0), Paths: gosemgrep.CliPaths{Scanned: []string{"./file"}}}); err != nil {
		t.Fatalf("want: %v got: %v", nil, err)
	}

}

func TestValidateFunc(t *testing.T) {
	report := ScanReport{Errors: make([]gosemgrep.CliError, 0)}
	report.Paths.Scanned = make([]string, 0)
	report.Results = append(report.Results, gosemgrep.CliMatch{Extra: gosemgrep.CliMatchExtra{Severity: "ERROR", Metadata: gosemgrep.CliMatchExtra{Severity: "ERROR"}}})

	testTable := []struct {
		label   string
		report  ScanReport
		config  Config
		wantErr error
	}{
		{label: "no-matches", report: ScanReport{}, config: Config{}, wantErr: nil},
		{label: "critical-found-allowed", report: report, config: Config{Error: -1}, wantErr: nil},
		{label: "critical-found-not-allowed", report: report, config: Config{Error: 0}, wantErr: gcv.ErrValidation},
	}

	for _, testCase := range testTable {
		t.Run(testCase.label, func(t *testing.T) {
			if err := validateFunc(testCase.report, testCase.config); !errors.Is(err, testCase.wantErr) {
				t.Fatalf("want: %v got: %v", testCase.wantErr, err)
			}
		})
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

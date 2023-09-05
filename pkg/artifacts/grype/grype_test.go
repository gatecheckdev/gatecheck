package grype

import (
	"bytes"
	"errors"
	"os"
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
	if grypeReport.String() == "" {
		t.Fatal("empty string for report.String()")
	}
}

func TestValidate(t *testing.T) {
	matches := []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-2", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-3", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-4", Severity: "High"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-5", Severity: "High"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-6", Severity: "Medium"}}},
	}

	type TestTable struct {
		label   string
		wantErr error
		config  Config
		matches []models.Match
	}
	testTable := []TestTable{
		{label: "fail-validation-1", matches: matches, config: Config{Critical: 0, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1},
			wantErr: gcv.ErrFailedRule},
		{label: "fail-validation-2", matches: matches, config: Config{Critical: 0, High: 1, Medium: 5, Low: -1, Negligible: -1, Unknown: -1},
			wantErr: gcv.ErrFailedRule},

		{label: "pass-validation-1", matches: matches, config: Config{Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1},
			wantErr: nil},
		{label: "pass-validation-2", matches: matches, config: Config{Critical: 4, High: 2, Medium: 5, Low: -1, Negligible: -1, Unknown: -1},
			wantErr: nil},
	}

	t.Run("threshold-rule", func(t *testing.T) {
		for _, testCase := range testTable {
			t.Run(testCase.label, func(t *testing.T) {
				err := ThresholdRule(testCase.matches, testCase.config)
				t.Log(err)
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("want: %v got: %v", gcv.ErrFailedRule, err)
				}
			})
		}
	})

	testTable = []TestTable{
		{label: "DenyList-1", matches: matches, config: Config{Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1,
			DenyList: []ListItem{{ID: "cve-1"}}}, wantErr: gcv.ErrFailedRule},
		{label: "DenyList-2", matches: matches, config: Config{Critical: 4, High: 2, Medium: 5, Low: -1, Negligible: -1, Unknown: -1,
			DenyList: []ListItem{{ID: "cve-1"}}}, wantErr: gcv.ErrFailedRule},
		{label: "DenyList-3", matches: matches, config: Config{Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1,
			DenyList: []ListItem{{ID: "cve-99"}}}, wantErr: nil},
	}

	t.Run("denyList-rule", func(t *testing.T) {
		for _, testCase := range testTable {
			t.Run(testCase.label, func(t *testing.T) {
				err := DenyListRule(testCase.matches, testCase.config)
				t.Log(err)
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("want: %v got: %v", gcv.ErrFailedRule, err)
				}
			})
		}
	})

	t.Run("allowList-rule", func(t *testing.T) {
		match := models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}}
		config := Config{Critical: 0, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1, AllowList: []ListItem{{ID: "cve-1"}}}
		if !AllowListRule(match, config) {
			t.Fatal("want true")
		}
	})
}

func TestValidator(t *testing.T) {
	matches := []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-2", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-3", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-4", Severity: "High"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-5", Severity: "High"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-6", Severity: "Medium"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-7", Severity: "Low"}}},
	}
	testCase := []struct {
		label   string
		wantErr error
		config  Config
	}{
		{label: "pass-validation-1", wantErr: nil, config: Config{Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1}},
		{label: "pass-validation-2", wantErr: nil, config: Config{Critical: 5, High: 5, Medium: -1, Low: -1, Negligible: -1, Unknown: -1}},

		{label: "fail-validation-1", wantErr: gcv.ErrFailedRule, config: Config{Critical: 0, High: 0, Medium: -1, Low: -1, Negligible: -1, Unknown: -1}},
		{label: "fail-validation-2", wantErr: gcv.ErrFailedRule, config: Config{Critical: 2, High: 1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1}},

		{label: "pass-validation-allowlist", wantErr: nil, config: Config{Critical: -1, High: -1, Medium: -1, Low: 0, Negligible: -1, Unknown: -1,
			AllowList: []ListItem{{ID: "cve-7"}}}},

		{label: "fail-validation-denylist", wantErr: gcv.ErrFailedRule, config: Config{Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1,
			DenyList: []ListItem{{ID: "cve-1"}}}},
	}

	for _, testCase := range testCase {
		t.Run(testCase.label, func(t *testing.T) {

			err := NewValidator().Validate(matches, testCase.config)
			t.Log(err)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("want: %v got: %v", testCase.wantErr, err)
			}
		})
	}

	t.Run("readConfigAndValidate", func(t *testing.T) {
		config := Config{Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1}
		configBuf := new(bytes.Buffer)
		_ = yaml.NewEncoder(configBuf).Encode(map[string]any{ConfigFieldName: config})

		err := NewValidator().ReadConfigAndValidate(matches, configBuf, ConfigFieldName)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestCheckReport(t *testing.T) {
	if err := checkReport(nil); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}
	if err := checkReport(&ScanReport{}); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}
	report := &ScanReport{}
	report.Descriptor.Name = "grype"
	if err := checkReport(report); err != nil {
		t.Fatal(err)
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

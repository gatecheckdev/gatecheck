package gitleaks

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

const TestReport string = "../../../test/gitleaks-report.json"

func TestEncoding(t *testing.T) {
	t.Run("sucess", func(t *testing.T) {
		decoder := NewReportDecoder()
		obj, err := decoder.DecodeFrom(MustOpen(TestReport, t))
		if err != nil {
			t.Fatal(err)
		}
		report, ok := obj.(*ScanReport)
		if !ok {
			t.Fatalf("want: *ScanReport got: %T", obj)
		}
		if len(*report) < 2 {
			t.Fatalf("want: <2 got: %d", len(*report))
		}

		t.Log(report.String())
		t.Log(decoder.FileType())
		if !strings.Contains(report.String(), "generic-api-key") {
			t.Fatal("'generic-api-key' should exist in string")
		}
	})
	t.Run("invalid-report", func(t *testing.T) {
		decoder := NewReportDecoder()
		_, err := decoder.DecodeFrom(strings.NewReader("[{\"name\":\"bacchus\"}]\n"))
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})
	t.Run("no-serects", func(t *testing.T) {
		decoder := NewReportDecoder()
		obj, err := decoder.DecodeFrom(strings.NewReader("[]\n"))
		if err != nil {
			t.Fatal(err)
		}
		report, ok := obj.(*ScanReport)
		if !ok {
			t.Fatalf("want: *ScanReport got: %T", obj)
		}
		t.Log(report)
	})
}

type badReader struct{}

func (r *badReader) Read(_ []byte) (int, error) {
	return 0, errors.New("error")
}

func TestEncoding_EdgeCases(t *testing.T) {
	t.Run("bad-reader", func(t *testing.T) {
		_, err := NewReportDecoder().DecodeFrom(&badReader{})
		if err == nil {
			t.Fatal("want error for bad reader")
		}
	})

	t.Run("bad-file", func(t *testing.T) {
		_, err := NewReportDecoder().DecodeFrom(strings.NewReader("{{"))
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})

	t.Run("blank-report", func(t *testing.T) {
		_, err := NewReportDecoder().DecodeFrom(strings.NewReader("[]"))
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("missing-rule-id", func(t *testing.T) {
		buf := new(bytes.Buffer)
		report := ScanReport{Finding{}, Finding{}}
		json.NewEncoder(buf).Encode(report)
		_, err := NewReportDecoder().DecodeFrom(buf)
		if !errors.Is(err, gce.ErrFailedCheck) {
			t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
		}
	})
}

func TestValidation_success(t *testing.T) {
	reportFile := MustOpen(TestReport, t)
	r, _ := NewReportDecoder().DecodeFrom(reportFile)
	report := r.(*ScanReport)
	err := NewValidator().Validate(*report, Config{SecretsAllowed: false})

	t.Log(err)
	if !errors.Is(err, gcv.ErrFailedRule) {
		t.Fatalf("want: %v got: %v", gcv.ErrFailedRule, err)
	}
}

func TestValidateFunc(t *testing.T) {
	report := ScanReport{
		Finding{Description: "Some desc", Secret: "Some secret", RuleID: "abc-123"},
		Finding{Description: "Some desc 2", Secret: "Some secret 2", RuleID: "abc-124"},
	}

	testTable := []struct {
		label   string
		report  ScanReport
		config  Config
		wantErr error
	}{
		{label: "no-matches", report: ScanReport{}, config: Config{}, wantErr: nil},
		{label: "critical-found-allowed", report: report, config: Config{SecretsAllowed: true}, wantErr: nil},
		{label: "critical-found-not-allowed", report: report, config: Config{SecretsAllowed: false}, wantErr: gcv.ErrFailedRule},
	}

	for _, testCase := range testTable {
		t.Run(testCase.label, func(t *testing.T) {
			if err := NewValidator().Validate(testCase.report, testCase.config); !errors.Is(err, testCase.wantErr) {
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

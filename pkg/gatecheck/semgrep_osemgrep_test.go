package gatecheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
)

func TestOsemgrepReportParses(t *testing.T) {
	body, err := os.ReadFile("../../test/semgrep-osemgrep-report.json")
	if err != nil {
		t.Fatal(err)
	}

	var report artifacts.SemgrepReportMin
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Version != "1.182.1" {
		t.Fatalf("version %s", report.Version)
	}
	if len(report.Results) != 1 {
		t.Fatalf("results %d", len(report.Results))
	}
	finding := report.Results[0]
	if finding.CheckID != "-" || finding.Extra.Severity != "ERROR" || finding.Extra.Message != "eval(x)" {
		t.Fatalf("finding %+v", finding)
	}
	if finding.Extra.Metadata.OwaspIDs() != "-" {
		t.Fatalf("owasp %s", finding.Extra.Metadata.OwaspIDs())
	}
	if len(report.SelectBySeverity("error")) != 1 {
		t.Fatal("severity ERROR was not selected")
	}

	var listed bytes.Buffer
	if err := List(&listed, bytes.NewReader(body), "semgrep-osemgrep-report.json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listed.String(), "ERROR") {
		t.Fatalf("list output %s", listed.String())
	}

	config := NewDefaultConfig()
	config.Semgrep.SeverityLimit.Error.Enabled = true
	config.Semgrep.SeverityLimit.Error.Limit = 0
	err = validateSemgrepReport(bytes.NewReader(body), config)
	if !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("validate %v", err)
	}
}

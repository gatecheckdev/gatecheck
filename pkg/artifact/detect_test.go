package artifact

import (
	"bytes"
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
	"io"
	"os"
	"testing"
)

func TestDetectGitleaks(t *testing.T) {
	gitleaksScanReport := entity.GitLeaksScanReport{
		entity.GitleaksFinding{Description: "Some Description 1"},
		entity.GitleaksFinding{Description: "Some Description 2"},
		entity.GitleaksFinding{Description: "Some Description 3"},
	}
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(gitleaksScanReport)

	TestTable := []DetectorTestCase{
		{Case: buf, Expected: Gitleaks},
		{Case: badReader{}, Expected: Unsupported},
		{Case: bytes.NewBuffer([]byte("[]")), Expected: Gitleaks},
		{Case: bytes.NewBuffer([]byte("{{")), Expected: Unsupported},
	}

	for _, item := range TestTable {
		if rType := detectGitleaks(item.Case); rType != item.Expected {
			t.Fatalf("Expected %s for %+v, Got %s", item.Expected, item.Case, rType)
		}
	}
}

func TestDetectSemgrep(t *testing.T) {

	semgrepScanReport := entity.SemgrepScanReport{Version: "1.1.1"}

	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(semgrepScanReport)

	testTable := []DetectorTestCase{
		{Case: badReader{}, Expected: Unsupported},
		{Case: buf, Expected: Semgrep},
	}

	for _, item := range testTable {
		if rType := detectSemgrep(item.Case); rType != item.Expected {
			t.Fatalf("Expected %s for %+v, Got %s", item.Expected, item.Case, rType)
		}
	}
}

func TestDetectGrype(t *testing.T) {
	f, err := os.Open("../../test/grype-report.json")
	if err != nil {
		t.FailNow()
	}

	testTable := []DetectorTestCase{
		{Case: badReader{}, Expected: Unsupported},
		{Case: f, Expected: Grype},
	}

	for _, item := range testTable {
		if rType := detectGrype(item.Case); rType != item.Expected {
			t.Fatalf("Expected %s for %+v, Got %s", item.Expected, item.Case, rType)
		}
	}
}

func TestDetectedReportType(t *testing.T) {
	f, err := os.Open("../../test/grype-report.json")
	if err != nil {
		t.FailNow()
	}

	testTable := []DetectorTestCase{
		{Case: f, Expected: Grype},
		{Case: badReader{}, Expected: Unsupported},
		{Case: bytes.NewBufferString("unsupported file content"), Expected: Unsupported},
	}

	for _, item := range testTable {
		if rType := DetectedReportType(item.Case); rType != item.Expected {
			t.Fatalf("Expected %s for %+v, Got %s", item.Expected, item.Case, rType)
		}
	}
}

// Test Structs

type DetectorTestCase struct {
	Case     io.Reader
	Expected ReportType
}

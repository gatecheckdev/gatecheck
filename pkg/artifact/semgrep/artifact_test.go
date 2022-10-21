package semgrep

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/fields"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
	"testing"
)

func TestArtifact_WithConfig(t *testing.T) {
	a := NewArtifact().WithConfig(NewConfig(1))
	t.Log(a.String())
	for _, finding := range []fields.Finding{a.Error, a.Warning, a.Info} {
		if finding.Allowed != 1 {
			t.Fatal("Expected all findings.Allowed to equal 1")
		}
		if finding.Found != 0 {
			t.Fatal("Expected all findings.Found to equal 0")
		}
	}

	a = a.WithConfig(nil)
	t.Log(a.String())
}

func TestArtifact_WithScanReport(t *testing.T) {
	report := new(entity.SemgrepScanReport)

	// Slimmed down Semgrep Report
	reportString := `{"results":[
{"extra":{"severity": "INFO"}},{"extra":{"severity": "INFO"}},{"extra":{"severity": "INFO"}},
{"extra":{"severity": "WARNING"}},{"extra":{"severity": "WARNING"}},{"extra":{"severity": "ERROR"}}
]}`

	_ = json.NewDecoder(bytes.NewBufferString(reportString)).Decode(report)

	a := NewArtifact().WithConfig(NewConfig(1))
	a, err := a.WithScanReport(bytes.NewBufferString(reportString), "test-report")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(a)
	if a.Info.Found != 3 || a.Warning.Found != 2 || a.Error.Found != 1 {
		t.Fatal("Decode failed")
	}

	t.Run("bad-reader", func(t *testing.T) {
		if _, err := NewArtifact().WithScanReport(new(badReader), ""); err == nil {
			t.Fatal("Expected error for bad reader")
		}
	})

	t.Run("bad-decode", func(t *testing.T) {
		if _, err := NewArtifact().WithScanReport(bytes.NewBufferString("\\\\"), ""); err == nil {
			t.Fatal("Expected error for bad decode")
		}
	})

}

func TestArtifact_Validate(t *testing.T) {
	artifact := NewArtifact()
	artifact.Error.Found = 50
	if err := artifact.WithConfig(NewConfig(0)).Validate(); err == nil {
		t.Fatal("No Vulnerabilities Allowed")
	}

	if err := artifact.WithConfig(NewConfig(-1)).Validate(); err != nil {
		t.Fatalf("All Vulnerabilities Allowed but validation failed. %v", err)
	}
}

type badReader struct{}

func (_ badReader) Read([]byte) (int, error) {
	return 0, errors.New("mock error")
}

package gatecheck

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// lcov --capture without --branch-coverage writes no BRF/BRH records.
const lcovNoBranches = `TN:
SF:main.go
FN:1,main
FNDA:1,main
FNF:1
FNH:1
DA:1,1
DA:2,0
LF:2
LH:1
end_of_record
`

func TestLCOVWithoutBranchRecords(t *testing.T) {
	got := renderList(t, "coverage.info", []byte(lcovNoBranches), nil)
	if strings.Contains(got, "NaN") {
		t.Fatalf("rendered NaN:\n%s", got)
	}
	for _, needle := range []string{"50.00%", "100.00%", "N/A"} {
		if !strings.Contains(got, needle) {
			t.Fatalf("missing %q\n%s", needle, got)
		}
	}

	config := NewDefaultConfig()
	config.Coverage.BranchThreshold = 0.8
	if err := Validate(config, bytes.NewReader([]byte(lcovNoBranches)), "coverage.info"); err != nil {
		t.Fatalf("branch threshold applied with no branch records: %v", err)
	}

	config.Coverage.LineThreshold = 0.8
	err := Validate(config, bytes.NewReader([]byte(lcovNoBranches)), "coverage.info")
	if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "Line coverage below threshold") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "Branch") {
		t.Fatalf("branch threshold failed with no branch records: %v", err)
	}
}

package fields

import (
	"strings"
	"testing"
)

func TestValidateFindings(t *testing.T) {

	t.Run("validation-all-allowed", func(t *testing.T) {
		// All vulnerabilities should be allowed
		findings := []Finding{
			{Severity: "Critical", Found: 12, Allowed: -1},
			{Severity: "High", Found: 15, Allowed: -1},
			{Severity: "Medium", Found: 43, Allowed: -1},
		}

		if err := ValidateFindings(findings); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("validation-some-allowed", func(t *testing.T) {
		findings := []Finding{
			{Severity: "Critical", Found: 1, Allowed: 2},
			{Severity: "High", Found: 5000, Allowed: 0},
			{Severity: "Medium", Found: 2938, Allowed: 0},
		}

		if err := ValidateFindings(findings); err == nil {
			t.Fatal("Expected validation error")
		}
	})

	t.Run("No vulnerabilities allowed", func(t *testing.T) {
		findings := []Finding{
			{Severity: "Critical", Found: 12, Allowed: 0},
			{Severity: "High", Found: 0, Allowed: 0},
			{Severity: "Medium", Found: 0, Allowed: 0},
		}

		if err := ValidateFindings(findings); err == nil {
			t.Fatal("Expected validation error")
		}
	})
}

func TestFinding_String(t *testing.T) {

	t.Run("fail-1", func(t *testing.T) {
		finding := Finding{Found: 2, Allowed: 1}
		if err := finding.Test(); err == nil {
			t.Fatalf("Should fail, %v", finding)
		}
		if strings.Contains(finding.String(), "False") != true {
			t.Fatalf("String does not contain False, %v", finding)
		}
	})

	t.Run("pass-1", func(t *testing.T) {
		finding := Finding{Found: 20, Allowed: -1}
		if err := finding.Test(); err != nil {
			t.Fatalf("Should pass, %v", finding)
		}
		if strings.Contains(finding.String(), "True") != true {
			t.Fatalf("String does not contain True, %v", finding)
		}
	})

	t.Run("fail-2", func(t *testing.T) {
		finding := Finding{Found: 1, Allowed: 0}
		if err := finding.Test(); err == nil {
			t.Fatalf("Should fail, %v", finding)
		}
		if strings.Contains(finding.String(), "False") != true {
			t.Fatalf("String does not contain False, %v", finding)
		}
	})

	t.Run("pass-2", func(t *testing.T) {
		finding := Finding{Found: 0, Allowed: 0}
		if err := finding.Test(); err != nil {
			t.Fatalf("Should pass, %v", finding)
		}
		if strings.Contains(finding.String(), "True") != true {
			t.Fatalf("String does not contain True, %v", finding)
		}
	})
}

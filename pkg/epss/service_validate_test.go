package epss

import (
	"errors"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

func TestService_Validation(t *testing.T) {
	service := &Service{
		dataStore: map[string]Scores{
			"cve-1": {EPSS: "0.1000", Percentile: "0.1000"},
			"cve-2": {EPSS: "0.2000", Percentile: "0.2000"},
			"cve-3": {EPSS: "0.3000", Percentile: "0.3000"},
			"cve-4": {EPSS: "0.4000", Percentile: "0.4000"},
			"cve-5": {EPSS: "0.5000", Percentile: "0.5000"},
		},
	}

	matches := []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-2", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-3", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-4", Severity: "High"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-5", Severity: "High"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-6", Severity: "High"}}},
	}

	t.Run("pass-deny-validation", func(t *testing.T) {
		config := grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1}
		err := service.GrypeDenyRuleFunc()(matches, config)
		t.Log(err)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("fail-deny-validation", func(t *testing.T) {
		config := grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1, EPSSDenyThreshold: .3}
		err := service.GrypeDenyRuleFunc()(matches, config)
		t.Log(err)
		if !errors.Is(err, gcv.ErrFailedRule) {
			t.Fatalf("want: %v got: %v", gcv.ErrFailedRule, err)
		}
	})

	t.Run("allow-validation-1", func(t *testing.T) {
		config := grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1}
		allowed := service.GrypeAllowRuleFunc()(matches[0], config)
		if allowed {
			t.Fatal("Should not be allowed")
		}
	})

	t.Run("allow-validation-2", func(t *testing.T) {
		config := grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1, EPSSAllowThreshold: .5}
		allowed := service.GrypeAllowRuleFunc()(matches[0], config)
		if !allowed {
			t.Fatal("Should be allowed")
		}
	})
}

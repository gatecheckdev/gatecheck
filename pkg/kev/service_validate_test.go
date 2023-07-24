package kev

import (
	"errors"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

func TestService_Validation(t *testing.T) {
	service := &Service{
		catalog: &Catalog{Vulnerabilities: []Vulnerability{
			{CveID: "cve-1"}, {CveID: "cve-2"}, {CveID: "cve-3"}, {CveID: "cve-4"}, {CveID: "cve-5"},
		}},
	}

	matches := []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-2", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-3", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-4", Severity: "High"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-5", Severity: "High"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-6", Severity: "High"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-7", Severity: "High"}}},
	}

	t.Run("pass-deny-validation", func(t *testing.T) {
		err := service.GrypeDenyRuleFunc()(matches[5:], grype.Config{})
		t.Log(err)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("fail-deny-validation", func(t *testing.T) {
		err := service.GrypeDenyRuleFunc()(matches, grype.Config{})
		t.Log(err)
		if !errors.Is(err, gcv.ErrFailedRule) {
			t.Fatal(err)
		}
	})

	err := service.NewValidator().Validate(matches, grype.Config{})
	t.Log(err)
	if !errors.Is(err, gcv.ErrFailedRule) {
		t.Fatalf("want: %v got: %v", gcv.ErrFailedRule, err)
	}
}

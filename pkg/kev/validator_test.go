package kev

import (
	"errors"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

func TestValidator_Validate(t *testing.T) {
	t.Run("success-pass", func(t *testing.T) {
		validator := NewValidator(&mockVulMatcher{returnMatches: make([]models.Match, 0)})
		if err := validator.Validate(nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("success-fail-1", func(t *testing.T) {
		denied := []models.Match{
			{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1"}}},
		}

		err := NewValidator(&mockVulMatcher{returnMatches: denied}).Validate(nil)
		t.Log(err)
		if !errors.Is(err, gcv.ErrValidation) {
			t.Fatalf("want: %v got: %v", gcv.ErrValidation, err)
		}
	})
	t.Run("success-fail-2", func(t *testing.T) {
		denied := []models.Match{
			{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1"}}},
			{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-2"}}},
		}

		err := NewValidator(&mockVulMatcher{returnMatches: denied}).Validate(nil)
		t.Log(err)
		if !errors.Is(err, gcv.ErrValidation) {
			t.Fatalf("want: %v got: %v", gcv.ErrValidation, err)
		}
	})
}

type mockVulMatcher struct {
	returnMatches []models.Match
}

func (m *mockVulMatcher) MatchedVulnerabilities(r *grype.ScanReport) []models.Match {
	return m.returnMatches
}

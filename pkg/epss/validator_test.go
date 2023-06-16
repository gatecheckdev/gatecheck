package epss

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"gopkg.in/yaml.v3"
)

func TestValidator_Validate(t *testing.T) {
	matches := []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-2", Severity: "High"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-3", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-4", Severity: "Low"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-5", Severity: "Medium"}}},
	}

	service := &Service{
		dataStore: map[string]Scores{
			"cve-1": {EPSS: fmt.Sprintf("%.5f", 0.42), Percentile: fmt.Sprintf("%.5f", 0.42)},
			"cve-2": {EPSS: fmt.Sprintf("%.5f", 0.39), Percentile: fmt.Sprintf("%.5f", 0.42)},
			"cve-3": {EPSS: fmt.Sprintf("%.5f", 0.14), Percentile: fmt.Sprintf("%.5f", 0.42)},
			"cve-4": {EPSS: fmt.Sprintf("%.5f", 0.49), Percentile: fmt.Sprintf("%.5f", 0.42)},
			"cve-5": {EPSS: fmt.Sprintf("%.5f", 0.50), Percentile: fmt.Sprintf("%.5f", 0.42)},
		},
	}

	t.Run("success-pass", func(t *testing.T) {
		configMap := map[string]any{grype.ConfigFieldName: grype.Config{EPSSAllowThreshold: .5}}
		configBuf := new(bytes.Buffer)
		_ = yaml.NewEncoder(configBuf).Encode(configMap)

		err := NewValidator(service).Validate(matches, configBuf)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("success-fail", func(t *testing.T) {
		configMap := map[string]any{grype.ConfigFieldName: grype.Config{EPSSAllowThreshold: .2, EPSSDenyThreshold: .45}}
		configBuf := new(bytes.Buffer)
		_ = yaml.NewEncoder(configBuf).Encode(configMap)
		err := NewValidator(service).Validate(matches, configBuf)
		t.Log(err)
		if !errors.Is(err, gcv.ErrValidation) {
			t.Fatalf("want: %v got: %v", gcv.ErrValidation, err)
		}
	})

	t.Run("missing-score", func(t *testing.T) {
		configMap := map[string]any{grype.ConfigFieldName: grype.Config{EPSSAllowThreshold: .5}}
		configBuf := new(bytes.Buffer)
		_ = yaml.NewEncoder(configBuf).Encode(configMap)

		matches := []models.Match{
			{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-6", Severity: "Critical"}}},
		}
		err := NewValidator(service).Validate(matches, configBuf)
		if err != nil {
			t.Fatal(err)
		}

	})

	t.Run("bad-config-missing-field", func(t *testing.T) {
		configMap := map[string]any{"blah": grype.Config{EPSSAllowThreshold: .2, EPSSDenyThreshold: .45}}
		configBuf := new(bytes.Buffer)
		_ = yaml.NewEncoder(configBuf).Encode(configMap)
		err := NewValidator(service).Validate(matches, configBuf)
		t.Log(err)
		if !errors.Is(err, gcv.ErrConfig) {
			t.Fatalf("want: %v got: %v", gcv.ErrConfig, err)
		}
	})

	t.Run("no-matches", func(t *testing.T) {
		configMap := map[string]any{grype.ConfigFieldName: grype.Config{EPSSAllowThreshold: .2, EPSSDenyThreshold: .45}}
		configBuf := new(bytes.Buffer)
		_ = yaml.NewEncoder(configBuf).Encode(configMap)
		err := NewValidator(service).Validate(make([]models.Match, 0), configBuf)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("parsing-error", func(t *testing.T) {
		configMap := map[string]any{grype.ConfigFieldName: grype.Config{EPSSAllowThreshold: .5}}
		configBuf := new(bytes.Buffer)
		_ = yaml.NewEncoder(configBuf).Encode(configMap)
		service := &Service{dataStore: map[string]Scores{"cve-1": {EPSS: "not a number", Percentile: fmt.Sprintf("%.5f", 0.42)}}}

		err := NewValidator(service).Validate(matches, configBuf)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})

}

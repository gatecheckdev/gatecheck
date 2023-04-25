package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	go_semgrep "github.com/BacchusJackson/go-semgrep"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/grype/grype/presenter/models"
)

func TestValidateGitleaks(t *testing.T) {
	gitleaksFile := MustReadFile("../../test/gitleaks-report.json", t.Fatal)

	var gitleaksScan GitleaksScanReport

	err := json.Unmarshal(gitleaksFile, &gitleaksScan)
	if err != nil {
		t.Fatal("cannot unmarshal object")
	}
	if strings.Contains(gitleaksScan.String(), "jwt") == false {
		t.Fatal("string formatting or unmarshalling failed")
	}

	if err := ValidateGitleaks(GitleaksConfig{SecretsAllowed: true}, gitleaksScan); err != nil {
		t.Fatal("Should pass")
	}

	if err := ValidateGitleaks(GitleaksConfig{SecretsAllowed: false}, gitleaksScan); errors.Is(err, GitleaksValidationFailed) != true {
		t.Fatal("Should Fail")
	}
	if err := ValidateGitleaks(GitleaksConfig{SecretsAllowed: false}, GitleaksScanReport{}); err != nil {
		t.Fatal("Should pass, len 0")
	}

}

func TestValidateCyclonedx(t *testing.T) {
	cyclonedxSbom := CyclonedxSbomReport{
		Vulnerabilities: &[]cdx.Vulnerability{
			{Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityCritical}}},
			{Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityCritical}}},
			{Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityCritical}}},
			{
				Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityHigh}},
				Affects: &[]cdx.Affects{{Ref: "ref1"}},
			},
		},
		Components: &[]cdx.Component{
			{BOMRef: "ref1", Name: "refName1", Version: "refVersion1", Type: cdx.ComponentTypeLibrary},
		},
	}

	if strings.Contains(cyclonedxSbom.String(), "Critical") == false {
		t.Fatal("string formatting failed")
	}

	if err := ValidateCyclonedx(CyclonedxConfig{Critical: 0}, cyclonedxSbom); errors.Is(err, ErrCyclonedxValidationFailed) != true {
		t.Log(cyclonedxSbom)
		t.Fatal("Expected Failed validation")
	}

	if err := ValidateCyclonedx(CyclonedxConfig{Critical: -1, High: -1}, cyclonedxSbom); err != nil {
		t.Log(cyclonedxSbom)
		t.Fatal("Expected passed validation")
	}

}

func TestValidateGrype(t *testing.T) {
	grypeScan := GrypeScanReport{Matches: []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{Severity: "High"}}},
	}}

	if strings.Contains(grypeScan.String(), "Critical") == false {
		t.Fatal("string formatting failed")
	}

	if err := ValidateGrype(GrypeConfig{Critical: 0}, grypeScan); errors.Is(err, GrypeValidationFailed) != true {
		t.Log(grypeScan)
		t.Fatal("Expected Failed validation")
	}

	if err := ValidateGrype(GrypeConfig{Critical: -1, High: -1}, grypeScan); err != nil {
		t.Log(grypeScan)
		t.Fatal("Expected passed validation")
	}

}

func TestValidateSemgrep(t *testing.T) {

	semgrepScan := SemgrepScanReport{Results: []go_semgrep.CliMatch{
		{Extra: go_semgrep.CliMatchExtra_1{Severity: "WARNING"}},
		{Extra: go_semgrep.CliMatchExtra_1{Severity: "WARNING"}},
		{Extra: go_semgrep.CliMatchExtra_1{Severity: "WARNING"}},
		{Extra: go_semgrep.CliMatchExtra_1{Severity: "ERROR",
			Metadata: map[string]interface{}{"shortlink": "gatecheck.dev/1"}}},
	}}

	if strings.Contains(semgrepScan.String(), "WARNING") == false {
		t.Fatal("string formatting failed")
	}

	if err := ValidateSemgrep(SemgrepConfig{Warning: 0}, semgrepScan); errors.Is(err, SemgrepFailedValidation) != true {
		t.Log(semgrepScan)
		t.Fatal("Expected Failed validation")
	}

	if err := ValidateSemgrep(SemgrepConfig{Warning: -1, Error: -1}, semgrepScan); err != nil {
		t.Log(semgrepScan)
		t.Fatal("Expected passed validation")
	}

	t.Log(ValidateSemgrep(SemgrepConfig{Warning: 0}, semgrepScan))
}

func TestEncoding(t *testing.T) {
	content := MustReadFile("../../test/grype-report.json", t.Fatal)

	var scan GrypeScanReport

	if err := json.NewDecoder(bytes.NewBuffer(content)).Decode(&scan); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(scan.String(), "Negligible") == false {
		t.Log("Expected Negligible in table")
		t.Fatal(scan.String())
	}

	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(&scan); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(buf.String(), "Negligible") == false {
		t.Log("Expected Negligible in table")
		t.Fatal(scan.String())
	}
}

func TestNewArtifact(t *testing.T) {
	grypeBytes := MustReadFile("../../test/grype-report.json", t.Fatal)
	artifact, err := NewArtifact("grype-report.json", bytes.NewBuffer(grypeBytes))
	if err != nil {
		t.Fatal(err)
	}

	if len(artifact.ContentBytes()) < 1000 {
		t.Fatal("Expected content length of 1,000")
	}

	if len(artifact.DigestString()) != 64 {
		t.Fatal("expected Digest length of 64 bytes")
	}

	if _, err := NewArtifact("bad", badReadWriter{}); err == nil {
		t.Fatal("Expected error for bad reader")
	}

}

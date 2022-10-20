package gitleaks

import (
	"bytes"
	"errors"
	"testing"
)

func TestArtifact(t *testing.T) {
	gitleaksReport, err := NewArtifact().WithScanReport(
		bytes.NewBufferString(sampleGitleaks), "sample-gitleaks.json")

	if err != nil {
		t.Fatal(err)
	}

	if gitleaksReport.SecretsFound != 2 {
		t.Fatalf("Secrets Found: %d, Secrets Expected: 2", gitleaksReport.SecretsFound)
	}

	if err := gitleaksReport.Validate(); err == nil {
		t.Fatal("Expected validation to fail")
	}
	t.Log(gitleaksReport)

	gitleaksReport = gitleaksReport.WithConfig(NewConfig(true))

	if err := gitleaksReport.Validate(); err != nil {
		t.Fatal("Expected validation to pass")
	}
	t.Log(gitleaksReport)

	gitleaksReport.SecretsFound = 0
	gitleaksReport.SecretsAllowed = false
	if err := gitleaksReport.Validate(); err != nil {
		t.Fatal("Expected validation to pass")
	}

	t.Run("bad-reader", func(t *testing.T) {
		if _, err := NewArtifact().WithScanReport(new(mockReader), ""); err == nil {
			t.Fatal("Expected error for bad reader")
		}
	})

	t.Run("bad-decode", func(t *testing.T) {
		r := bytes.NewBufferString("{BAD JSON")
		if _, err := NewArtifact().WithScanReport(r, ""); err == nil {
			t.Fatal("expected error for bad decode")
		}
	})

}

type mockReader struct{}

func (mockReader) Read([]byte) (int, error) {
	return 0, errors.New("Mock error")
}

const sampleGitleaks = `[
 {
  "Description": "JSON Web Token",
  "StartLine": 22,
  "EndLine": 22,
  "StartColumn": 17,
  "EndColumn": 176,
  "Match": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgzMDM3NzExfQ.gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8'",
  "Secret": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgzMDM3NzExfQ.gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8'",
  "File": "cypress/integration/e2e/forgedJwt.spec.ts",
  "SymlinkFile": "",
  "Commit": "1d1571854621f9fa4150e6fae93b24504d4e5a11",
  "Entropy": 5.6685553,
  "Author": "ShubhamPalriwala",
  "Email": "spalriwalau@gmail.com",
  "Date": "2022-09-12T11:22:42Z",
  "Message": "feat: lint cypress dir and add dir to tsconfig",
  "Tags": [],
  "RuleID": "jwt",
  "Fingerprint": "1d1571854621f9fa4150e6fae93b24504d4e5a11:cypress/integration/e2e/forgedJwt.spec.ts:jwt:22"
 },
 {
  "Description": "Generic API Key",
  "StartLine": 7,
  "EndLine": 7,
  "StartColumn": 14,
  "EndColumn": 55,
  "Match": "Secret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'",
  "Secret": "IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH",
  "File": "cypress/integration/e2e/totpSetup.spec.ts",
  "SymlinkFile": "",
  "Commit": "1d1571854621f9fa4150e6fae93b24504d4e5a11",
  "Entropy": 4.35141,
  "Author": "ShubhamPalriwala",
  "Email": "spalriwalau@gmail.com",
  "Date": "2022-09-12T11:22:42Z",
  "Message": "feat: lint cypress dir and add dir to tsconfig",
  "Tags": [],
  "RuleID": "generic-api-key",
  "Fingerprint": "1d1571854621f9fa4150e6fae93b24504d4e5a11:cypress/integration/e2e/totpSetup.spec.ts:generic-api-key:7"
 }]`

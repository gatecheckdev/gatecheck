package grype

import (
	"bytes"
	"errors"
	"gopkg.in/yaml.v3"
	"os"
	"testing"
)

const TestGrypeReportFilename = "../../../test/grype-report.json"

func TestArtifact_WithConfig(t *testing.T) {
	artifact := NewArtifact()

	artifact = artifact.WithConfig(NewConfig(10))

	configString := "critical: 10\nhigh: 10\nmedium: 10\nlow: 10\nnegligible: 10\nunknown: 10\n"
	config := new(Config)
	if err := yaml.NewDecoder(bytes.NewBufferString(configString)).Decode(config); err != nil {
		t.Fatal(err)
	}
	secondArtifact := NewArtifact().WithConfig(config)

	if artifact.Critical != secondArtifact.Critical {
		t.Fatal("Artifact from config object and artifact from string do not match")
	}

	t.Log(artifact.String())

	t.Run("nil-config", func(t *testing.T) {
		artifact := NewArtifact()
		artifact = artifact.WithConfig(nil)
		t.Log(artifact)
	})
}

func TestArtifact_WithScanReport(t *testing.T) {

	scanFile, err := os.Open(TestGrypeReportFilename)
	if err != nil {
		t.Fatal(err)
	}

	grypeArtifact, err := NewArtifact().WithScanReport(scanFile, "grype-report.json")

	t.Log(grypeArtifact.String())

	if grypeArtifact.ScanReport.Label != "grype-report.json" {
		t.Log(grypeArtifact)
		t.Fatal("Expected Scan Report Metadata to equal 'grype-report.json'")
	}

	t.Run("bad-reader", func(t *testing.T) {
		if _, err := grypeArtifact.WithScanReport(new(badReader), ""); err == nil {
			t.Fatal("Expected error for bad reader")
		}
	})

	t.Run("bad-decode", func(t *testing.T) {
		if _, err := grypeArtifact.WithScanReport(bytes.NewBufferString("\\\\"), ""); err == nil {
			t.Fatal("Expected error for bad decode")
		}
	})
}

func TestArtifact_Validate(t *testing.T) {
	artifact := NewArtifact()
	artifact.Critical.Found = 50
	if err := artifact.WithConfig(NewConfig(0)).Validate(); err == nil {
		t.Fatal("No Vulnerabilities Allowed")
	}

	if err := artifact.WithConfig(NewConfig(-1)).Validate(); err != nil {
		t.Fatalf("All Vulnerabilities Allowed but validation failed. %v", err)
	}
}

// Mock objects

type badReader struct{}

func (r badReader) Read([]byte) (int, error) {
	return 0, errors.New("mock error")
}

package grype_test

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"gopkg.in/yaml.v2"
	"os"
	"testing"
)

const TestGrypeReportFilename = "../../../test/grype-report.json"

func TestArtifact_WithConfig(t *testing.T) {
	artifact := grype.NewArtifact()

	artifact = artifact.WithConfig(grype.NewConfig(10))

	configString := "critical: 10\nhigh: 10\nmedium: 10\nlow: 10\nnegligible: 10\nunknown: 10\n"
	config := new(grype.Config)
	if err := yaml.NewDecoder(bytes.NewBufferString(configString)).Decode(config); err != nil {
		t.Fatal(err)
	}
	secondArtifact := grype.NewArtifact().WithConfig(config)

	if artifact.Critical != secondArtifact.Critical {
		t.Fatal("Artifact from config object and artifact from string do not match")
	}

	t.Log(artifact)
}

func TestArtifact_WithScanReport(t *testing.T) {

	scanFile, err := os.Open(TestGrypeReportFilename)
	if err != nil {
		t.Fatal(err)
	}

	grypeArtifact, err := grype.NewArtifact().WithScanReport(scanFile, "grype-report.json")

	if grypeArtifact.ScanReport.Label != "grype-report.json" {
		t.Log(grypeArtifact)
		t.Fatal("Expected Scan Report Label to equal 'grype-report.json'")
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

type badReader struct{}

func (r badReader) Read([]byte) (int, error) {
	return 0, errors.New("mock error")
}

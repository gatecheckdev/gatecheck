package grype_test

import (
	"bytes"
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"gopkg.in/yaml.v2"
	"os"
	"testing"
)

func TestStandardArtifact_WithConfig(t *testing.T) {
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

func TestStandardArtifact_WithAsset(t *testing.T) {
	artifact := grype.NewArtifact()

	scanFile, err := os.Open(TestGrypeReport)
	if err != nil {
		t.Fatal(err)
	}

	scan := new(grype.ScanReport)
	if err := json.NewDecoder(scanFile).Decode(scan); err != nil {
		t.Fatal(err)
	}

	asset := grype.NewAsset("grype-report.json").WithScan(scan)

	artifact = artifact.WithAsset(asset)

	t.Log(artifact)

	t.Run("Write and Read Artifact", func(t *testing.T) {
		buf := new(bytes.Buffer)
		if err := json.NewEncoder(buf).Encode(artifact); err != nil {
			t.Fatal(err)
		}

		secondArtifact := new(grype.Artifact)
		if err := json.NewDecoder(buf).Decode(secondArtifact); err != nil {
			t.Fatal(err)
		}

		t.Log(secondArtifact)
	})

	t.Run("Write and Read Artifact Full", func(t *testing.T) {
		buf := new(bytes.Buffer)
		artifact = artifact.WithConfig(grype.NewConfig(50)).WithAsset(asset)

		if err := json.NewEncoder(buf).Encode(artifact); err != nil {
			t.Fatal(err)
		}

		if err := json.NewDecoder(buf).Decode(artifact); err != nil {
			t.Fatal(err)
		}
		t.Log(artifact)
	})
}

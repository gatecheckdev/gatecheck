package grype_test

import (
	"bytes"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"os"
	"testing"
)

func TestStandardArtifact_WithConfig(t *testing.T) {
	artifact := grype.NewArtifact()

	artifact = artifact.WithConfig(grype.NewConfig(10))

	configString := "critical: 10\nhigh: 10\nmedium: 10\nlow: 10\nnegligible: 10\nunknown: 10\n"
	config, _ := grype.NewConfigReader(bytes.NewBufferString(configString)).ReadConfig()
	secondArtifact := grype.NewArtifact().WithConfig(&config)

	if *artifact != *secondArtifact {
		t.Fatal("Artifact from config object and artifact from string do not match")
	}

	t.Log(artifact)
}

func TestStandardArtifact_WithAsset(t *testing.T) {
	artifact := grype.NewArtifact()

	scanFile, _ := os.Open(TestGrypeReport)
	scan, _ := grype.NewScanReportReader(scanFile).ReadScan()
	asset := grype.NewAsset("grype-report.json").WithScan(*scan)

	artifact = artifact.WithAsset(asset)

	t.Log(artifact)

	t.Run("Write and Read Artifact", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = grype.NewArtifactWriter(buf).WriteArtifact(artifact)
		secondArtifact, err := grype.NewArtifactReader(buf).ReadArtifact()
		if err != nil {
			t.Fatal(err)
		}
		t.Log(secondArtifact)
	})

	t.Run("Write and Read Artifact Full", func(t *testing.T) {
		buf := new(bytes.Buffer)
		artifact = artifact.WithConfig(grype.NewConfig(50)).WithAsset(asset)

		if err := grype.NewArtifactWriter(buf).WriteArtifact(artifact); err != nil {
			t.Fatal(err)
		}
		t.Log(artifact)
	})
}

package gatecheck

import (
	"bytes"
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/semgrep"
	"os"
	"strings"
	"testing"
)

var TestGrypeReport = "../../test/grype-report.json"

func TestWriteAndReadReport(t *testing.T) {
	buf := new(bytes.Buffer)
	rep := NewReport("Test Gatecheck Report")

	t.Run("encoding", func(t *testing.T) {
		if err := json.NewEncoder(buf).Encode(rep); err != nil {
			t.Fatal(err)
		}
		rep2 := new(Report)
		err := json.NewDecoder(buf).Decode(rep2)
		if err != nil {
			t.Fatal(err)
		}
		if rep2.ProjectName != "Test Gatecheck Report" {
			t.Logf("Encoded Report: %+v\n Decoded Report: %+v\n", rep, rep2)
			t.Fatal("Encoding failed")
		}
	})

	t.Run("with-grype-scan", func(t *testing.T) {
		scanFile, err := os.Open(TestGrypeReport)
		if err != nil {
			t.Fatal(err)
		}

		art := grype.NewArtifact().WithConfig(grype.NewConfig(-1))
		art, err = art.WithScanReport(scanFile, "grype-report.json")
		rep.Artifacts.Grype = art

		t.Log(rep)
	})

}

func TestReport_WithConfig(t *testing.T) {

	t.Run("grype", func(t *testing.T) {
		report := NewReport("Some project with grype")
		// nil config
		if report.WithConfig(nil).Artifacts.Grype != nil {
			t.Fatal("Unexpected value")
		}
		// good config
		config := &Config{Grype: grype.NewConfig(2)}
		if report.WithConfig(config).Artifacts.Grype.Critical.Allowed != 2 {
			t.Fatal("Configuration did not set")
		}
	})

	t.Run("semgrep", func(t *testing.T) {
		report := NewReport("Some project with semgrep")
		// nil config
		if report.WithConfig(nil).Artifacts.Semgrep != nil {
			t.Fatal("Unexpected value")
		}
		// good config
		config := &Config{Semgrep: semgrep.NewConfig(2)}
		if report.WithConfig(config).Artifacts.Semgrep.Error.Allowed != 2 {
			t.Fatal("Configuration did not set")
		}
	})

	t.Run("gitleaks", func(t *testing.T) {
		report := NewReport("Some project with gitleaks")
		// nil config
		if report.WithConfig(nil).Artifacts.Gitleaks != nil {
			t.Fatal("Unexpected value")
		}
		// good config
		config := &Config{Gitleaks: gitleaks.NewConfig(true)}
		if report.WithConfig(config).Artifacts.Gitleaks.SecretsAllowed != true {
			t.Fatal("Configuration did not set")
		}
	})

}

func TestReport_WithSettings(t *testing.T) {
	r := NewReport("Test Project Name")

	r = r.WithSettings(Settings{ProjectName: "New Project Name"})
	r = r.WithSettings(Settings{PipelineId: "ABC-12345"})
	r = r.WithSettings(Settings{PipelineUrl: "pipeline.com"})

	if strings.Compare(r.ProjectName, "New Project Name") != 0 {
		t.Fatal("Unexpected Project Name")
	}
	if strings.Compare(r.PipelineId, "ABC-12345") != 0 {
		t.Fatal("Unexpected Pipeline ID")
	}
	if strings.Compare(r.PipelineUrl, "pipeline.com") != 0 {
		t.Fatal("Unexpected Pipeline URL")
	}
}

func TestReport_Validate(t *testing.T) {
	r := NewReport("Test Report")

	r.Artifacts.Grype = grype.NewArtifact()
	r.Artifacts.Grype.Critical.Found = 20
	r.Artifacts.Grype.High.Found = 22
	r.Artifacts.Grype.Medium.Found = 113

	r.Artifacts.Semgrep = semgrep.NewArtifact()
	r.Artifacts.Semgrep.Error.Found = 12
	r.Artifacts.Semgrep.Warning.Found = 14
	r.Artifacts.Semgrep.Info.Found = 130

	t.Run("All Vulnerabilities allowed", func(t *testing.T) {
		// All vulnerabilities should be allowed
		c := NewConfig("Test Project")

		r = r.WithConfig(c)
		if err := r.Validate(); err != nil {
			t.Fatal("Validation should pass")
		}
	})

	t.Run("Some Allowed", func(t *testing.T) {
		c := NewConfig("Test Project")
		c.Grype.Critical = 0
		c.Grype.High = 1
		c.Grype.Medium = 2
		c.Grype.Low = 50
		c.Grype.Unknown = 0
		c.Grype.Negligible = 0

		c.Semgrep.Error = 0
		c.Semgrep.Warning = 20
		c.Semgrep.Info = -1
		r = r.WithConfig(c)

		if err := r.Validate(); err == nil {
			t.Fatal("Validation should fail")
		}

	})

	t.Run("No vulnerabilities allowed", func(t *testing.T) {
		c := NewConfig("Test Project")
		c.Grype = grype.NewConfig(0)
		c.Semgrep = semgrep.NewConfig(0)
		r = r.WithConfig(c)

		if err := r.Validate(); err == nil {
			t.Fatal("Validation should fail")
		}
	})

}

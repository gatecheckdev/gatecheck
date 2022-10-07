package gatecheck

import (
	"bytes"
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
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
		rep.Artifacts.Grype = *art

		t.Log(rep)
	})

	t.Run("with-config", func(t *testing.T) {
		tempConfig := NewConfig("Test Project")
		tempConfig.Grype.Low = 100
		tempConfig.ProjectName = "Some project name"

		rep = rep.WithConfig(tempConfig)
		t.Log(rep)

		if strings.Contains(rep.String(), tempConfig.ProjectName) != true {
			t.Fatal("Project name not updated")
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

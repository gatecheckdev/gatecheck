package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
	"github.com/gatecheckdev/gatecheck/pkg/exporter"
	"io"
	"os"
	"testing"
)

func TestExportGrypeCmd(t *testing.T) {
	actual := new(bytes.Buffer)
	command := NewRootCmd(mockExporter{})
	command.SetOut(actual)
	command.SetErr(actual)

	command.SetArgs([]string{"export", "defect-dojo", "grype", "some-nonexistent-file.bad-json"})

	if err := command.Execute(); err == nil {
		t.Fatal("Expected error for non-existent file")
	}
	t.Log(actual)

	actual = new(bytes.Buffer)

	tempFile, err := os.Open("../test/grype-report.json")
	if err != nil {
		t.Fatal(err)
	}

	command.SetArgs([]string{"export", "defect-dojo", "grype", tempFile.Name()})

	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	t.Log(actual)
}

func TestExportSemgrepCmd(t *testing.T) {
	actual := new(bytes.Buffer)
	command := NewRootCmd(mockExporter{})
	command.SetOut(actual)
	command.SetErr(actual)

	command.SetArgs([]string{"export", "defect-dojo", "semgrep", "some-nonexistent-file.bad-json"})

	if err := command.Execute(); errors.Is(err, ErrorFileNotExists) != true {
		t.Fatal("Expected error for non-existent file")
	}

	actual = new(bytes.Buffer)

	tempFile, err := os.Open("../test/semgrep-sast-report.json")
	if err != nil {
		t.Fatal(err)
	}

	command.SetArgs([]string{"export", "defect-dojo", "semgrep", tempFile.Name()})

	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
}

type mockExporter struct{}

func (m mockExporter) Export(reportFile io.Reader, scanType exporter.ScanType) error {
	switch scanType {
	case exporter.Grype:
		report := new(entity.GrypeScanReport)
		if err := json.NewDecoder(reportFile).Decode(report); err != nil {
			return err
		}
		if len(report.Matches) == 0 {
			return errors.New("zero matches decoded from report")
		}
	case exporter.Semgrep:
		report := new(entity.SemgrepScanReport)
		if err := json.NewDecoder(reportFile).Decode(report); err != nil {
			return err
		}
		if len(report.Results) == 0 {
			return errors.New("zero matches decoded from report")
		}
	}

	return nil
}

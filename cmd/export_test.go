package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
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

type mockExporter struct{}

func (m mockExporter) ExportGrype(reportFile io.Reader) error {
	var report entity.GrypeScanReport

	if err := json.NewDecoder(reportFile).Decode(&report); err != nil {
		return err
	}
	if len(report.Matches) == 0 {
		return errors.New("zero matches decoded from report")
	}
	return nil
}

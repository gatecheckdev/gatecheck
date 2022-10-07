package cmd

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/pkg/exporter/defectDojo"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"io"
	"os"
	"path"
	"testing"
)

const TestConfigFilename = "../test/gatecheck.yaml"
const TestReportFilename = "../test/gatecheck-report.json"

func TestValidateCmd(t *testing.T) {
	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{})
	command.SetOut(actual)
	command.SetErr(actual)

	t.Run("config-not-exists", func(t *testing.T) {
		command.SetArgs([]string{"validate"})
		if err := command.Execute(); errors.Is(err, ErrorFileNotExists) != true {
			t.Error(err)
			t.Fatal("Expected file not exists error")
		}
	})

	t.Run("fail-validation", func(t *testing.T) {

		command.SetArgs([]string{"validate", "-c", CopyToTemp(t, TestConfigFilename),
			"-r", CopyToTemp(t, TestReportFilename)})

		if err := command.Execute(); errors.Is(err, ErrorValidation) != true {
			t.Fatalf("Expected validation error, got %v", err)
		}

	})

	t.Run("audit", func(t *testing.T) {

		command.SetArgs([]string{"validate", "-c", CopyToTemp(t, TestConfigFilename),
			"-r", CopyToTemp(t, TestReportFilename), "-a"})

		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}

	})

	t.Run("validation", func(t *testing.T) {
		c := gatecheck.NewConfig("Test Project")
		tempConfigFilename := path.Join(os.TempDir(), "gatecheck.yaml")

		if err := OpenAndEncode(tempConfigFilename, YAML, c); err != nil {
			t.Fatal(err)
		}

		command.SetArgs([]string{"validate", "-c", tempConfigFilename, "-r", CopyToTemp(t, TestReportFilename)})

		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("report-file-access", func(t *testing.T) {
		command.SetArgs([]string{"validate", "-c", CopyToTemp(t, TestConfigFilename),
			"-r", CreateMockFile(t, NoPermissions)})

		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected file access error, got %v", err)
		}
	})

}

// Mock Functions

func CopyToTemp(t *testing.T, src string) string {

	srcFile, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}

	fPath := path.Join(t.TempDir(), path.Base(srcFile.Name()))
	destFile, err := os.Create(fPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := io.Copy(destFile, srcFile); err != nil {
		t.Fatal(err)
	}
	return fPath
}

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
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
	command := NewRootCmd(defectDojo.Exporter{}, mockService{})
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

func TestValidateBlacklistCmd(t *testing.T) {
	r := entity.GrypeScanReport{Matches: []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "B"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "C"}}},
	}}
	br := entity.KEVCatalog{Vulnerabilities: []entity.KEVCatalogVulnerability{
		{CveID: "A"},
		{CveID: "C"},
	}}
	tempReportFilename := path.Join(t.TempDir(), "grype-report.json")
	tempBlacklistFilename := path.Join(t.TempDir(), "blacklist.json")

	f, err := os.Create(tempReportFilename)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(f).Encode(r)

	f, err = os.Create(tempBlacklistFilename)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(f).Encode(br)

	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{}, mockService{})
	command.SetOut(actual)
	command.SetErr(actual)

	command.SetArgs([]string{"validate", "blacklist", tempReportFilename, tempBlacklistFilename})

	if err := command.Execute(); errors.Is(err, ErrorValidation) != true {
		t.Fatal("Expected validation to fail")
	}

	t.Run("bad-grype-file", func(t *testing.T) {
		// Non-existing file
		tempReportFilename := path.Join(t.TempDir(), "grype-report.json")

		command.SetArgs([]string{"validate", "blacklist", tempReportFilename, tempBlacklistFilename})
		if err := command.Execute(); errors.Is(err, ErrorDecode) != true {
			t.Fatal("Expected decode error for non-existing file")
		}
	})

	t.Run("bad-blacklist-file", func(t *testing.T) {
		// Non-existing file
		tempBlacklistFilename := path.Join(t.TempDir(), "blacklist.json")

		command.SetArgs([]string{"validate", "blacklist", tempReportFilename, tempBlacklistFilename})

		if err := command.Execute(); errors.Is(err, ErrorDecode) != true {
			t.Fatal("Expected decode error for non-existing file")
		}
	})

	t.Run("test-audit", func(t *testing.T) {
		command.SetArgs([]string{"validate", "blacklist", "--audit", tempReportFilename, tempBlacklistFilename})
		if err := command.Execute(); err != nil {
			t.Fatal("Expected decode error for non-existing file")
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

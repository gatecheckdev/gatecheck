package cmd

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/pkg/exporter/defectDojo"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"strings"
	"testing"
)

const TestGrypeFilename = "../test/grype-report.json"
const TestSemgrepFilename = "../test/semgrep-sast-report.json"
const TestGitleaksFilename = "../test/gitleaks-report.json"

func TestUpdateCmd(t *testing.T) {
	// Set up output capture
	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{})
	command.SetOut(actual)
	command.SetErr(actual)

	configFilename := CopyToTemp(t, TestConfigFilename)
	reportFilename := CopyToTemp(t, TestReportFilename)
	// Change the Critical Threshold
	c, err := OpenAndDecode[gatecheck.Config](configFilename, YAML)
	if err != nil {
		t.Fatal(err)
	}
	c.Grype.Critical = 112
	if err := OpenAndEncode(configFilename, YAML, c); err != nil {
		t.Fatal(err)
	}
	t.Log(configFilename)
	command.SetArgs([]string{"report", "update", "--config", configFilename, "--report", reportFilename})

	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}

	// Check if the report was indeed update
	r, err := OpenAndDecode[gatecheck.Report](reportFilename, JSON)
	if err != nil {
		t.Fatal(err)
	}

	if r.Artifacts.Grype.Critical.Allowed != 112 {
		t.Logf("%+v", r)
		t.Fatal("Report was not updated as expected")
	}

	t.Run("config-file-access", func(t *testing.T) {
		command.SetArgs([]string{"report", "update", "--config", "nofile.yaml"})

		if err := command.Execute(); errors.Is(err, ErrorFileNotExists) != true {
			t.Fatalf("Expected file not exists error, got %v", err)
		}
	})

	t.Run("report-file-access", func(t *testing.T) {

		command.SetArgs([]string{"report", "update", "--config", CopyToTemp(t, TestConfigFilename),
			"--report", CreateMockFile(t, NoPermissions)})

		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected File Access error, got %v", err)
		}
	})

	t.Run("config-file-encoding", func(t *testing.T) {

		command.SetArgs([]string{"report", "update", "--config", CreateMockFile(t, BadDecode),
			"--report", CopyToTemp(t, TestReportFilename)})

		if err := command.Execute(); errors.Is(err, ErrorDecode) != true {
			t.Fatalf("Expected Decode error, got %v", err)
		}
	})

	t.Run("Update flags", func(t *testing.T) {
		reportFilename := CopyToTemp(t, TestReportFilename)
		command.SetArgs([]string{"report", "update", "--config", CopyToTemp(t, TestConfigFilename),
			"--report", reportFilename, "--url", "test.com/pipeline"})

		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}

		r, err := OpenAndDecode[gatecheck.Report](reportFilename, JSON)
		if err != nil {
			t.Fatal(err)
		}

		if strings.Compare(r.PipelineUrl, "test.com/pipeline") != 0 {
			t.Logf("COMMAND OUTPUT: %s\n", actual)
			t.Log(r)
			t.Fatal("Pipeline url not updated")
		}
	})
}

func TestPrintCmd(t *testing.T) {
	// Set up output capture
	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{})
	command.SetOut(actual)
	command.SetErr(actual)

	command.SetArgs([]string{"report", "print", "--config", CopyToTemp(t, TestConfigFilename),
		"--report", CopyToTemp(t, TestReportFilename)})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	t.Log(actual.String())

	t.Run("bad-report", func(t *testing.T) {
		command.SetArgs([]string{"report", "print", "--config", CopyToTemp(t, TestConfigFilename),
			"--report", CreateMockFile(t, NoPermissions)})

		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
	})
}

func TestReportAddGrype(t *testing.T) {
	ReportAdd(t, "grype", TestGrypeFilename)
}

func TestReportAddSemgrep(t *testing.T) {
	ReportAdd(t, "semgrep", TestSemgrepFilename)
}

func TestReportAddGitleaks(t *testing.T) {
	ReportAdd(t, "gitleaks", TestGitleaksFilename)
}

// Generic Tests
func ReportAdd(t *testing.T, addCommand string, testScanReport string) {
	command := NewRootCmd(defectDojo.Exporter{})
	command.SilenceUsage = true

	tempGatecheckReport := CopyToTemp(t, TestReportFilename)
	command.SetArgs([]string{"report", "add", addCommand, "--config", CopyToTemp(t, TestConfigFilename),
		"--report", tempGatecheckReport, CopyToTemp(t, testScanReport)})

	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}

	command.SetArgs([]string{"report", "print", "--report", tempGatecheckReport})

	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}

	t.Run("bad-config", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", addCommand, "--config", CreateMockFile(t, NoPermissions),
			CopyToTemp(t, testScanReport)})

		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatal("Expected file access error")
		}
	})

	t.Run("bad-report", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", addCommand, "--config", CopyToTemp(t, TestConfigFilename),
			"--report", CreateMockFile(t, NoPermissions), CopyToTemp(t, testScanReport)})

		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatal("Expected file access error")
		}
	})

	t.Run("bad-scan", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", addCommand, "--config", CopyToTemp(t, TestConfigFilename),
			"--report", CopyToTemp(t, TestReportFilename), CreateMockFile(t, NoPermissions)})

		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatal("Expected file access error")
		}
	})

	t.Run("bad-scan-decode", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", addCommand, "--config", CopyToTemp(t, TestConfigFilename),
			"--report", CopyToTemp(t, TestReportFilename), CreateMockFile(t, BadDecode)})

		if err := command.Execute(); errors.Is(err, ErrorDecode) != true {
			t.Fatal("Expected file access error")
		}
	})
}

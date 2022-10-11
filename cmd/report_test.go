package cmd

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/pkg/exporter/defectDojo"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"path"
	"strings"
	"testing"
)

const TestGrypeFilename = "../test/grype-report.json"
const TestSemgrepFilename = "../test/semgrep-sast-report.json"

func TestAddGrypeCmd(t *testing.T) {
	// Set up output captureA
	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{})
	command.SetOut(actual)
	command.SetErr(actual)

	t.Run("bad config", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", "grype", CopyToTemp(t, TestGrypeFilename)})

		if err := command.Execute(); errors.Is(err, ErrorFileNotExists) != true {
			t.Fatal(err)
		}
	})

	t.Run("bad report", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", "grype", "--config", CreateMockFile(t, BadDecode),
			"--report", CopyToTemp(t, TestReportFilename), CopyToTemp(t, TestGrypeFilename)})

		if err := command.Execute(); errors.Is(err, ErrorDecode) != true {
			t.Fatal(err)
		}
	})

	t.Run("bad-scan", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", "grype", "--config", CopyToTemp(t, TestConfigFilename),
			"--report", CopyToTemp(t, TestReportFilename), CreateMockFile(t, BadDecode)})

		if err := command.Execute(); errors.Is(err, ErrorDecode) != true {
			t.Fatal(err)
		}
	})

	t.Run("report-file-access", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", "grype", "--config", CopyToTemp(t, TestConfigFilename),
			"--report", CreateMockFile(t, NoPermissions), CreateMockFile(t, NoPermissions)})

		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
	})

	t.Run("file-access", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", "grype", "--config", CopyToTemp(t, TestConfigFilename),
			"--report", CopyToTemp(t, TestReportFilename), CreateMockFile(t, NoPermissions)})

		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
	})

	t.Run("success", func(t *testing.T) {
		newReportFilename := path.Join(t.TempDir(), "gatecheck-report.json")

		command.SetArgs([]string{"report", "add", "grype", "--config", CopyToTemp(t, TestConfigFilename),
			"--report", newReportFilename, CopyToTemp(t, TestGrypeFilename)})

		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}

		// Check if the created file can be decoded
		gatecheckReport, err := OpenAndDecode[gatecheck.Report](newReportFilename, JSON)
		if err != nil {
			t.Fatal(err)
		}
		if len(gatecheckReport.Artifacts.Grype.ScanReport.Digest) == 0 {
			t.Fatal("Scan Report Digest is blank")
		}
	})
}

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

func TestReportAddSemgrep(t *testing.T) {
	command := NewRootCmd(defectDojo.Exporter{})

	command.SetArgs([]string{"report", "add", "semgrep", "--config", CopyToTemp(t, TestConfigFilename),
		"--report", CopyToTemp(t, TestReportFilename), CopyToTemp(t, TestSemgrepFilename)})

	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}

	t.Run("bad-config", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", "semgrep", "--config", CreateMockFile(t, NoPermissions),
			CopyToTemp(t, TestSemgrepFilename)})

		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatal("Expected file access error")
		}
	})

	t.Run("bad-report", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", "semgrep", "--config", CopyToTemp(t, TestConfigFilename),
			"--report", CreateMockFile(t, NoPermissions), CopyToTemp(t, TestSemgrepFilename)})

		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatal("Expected file access error")
		}
	})

	t.Run("bad-scan", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", "semgrep", "--config", CopyToTemp(t, TestConfigFilename),
			"--report", CopyToTemp(t, TestReportFilename), CreateMockFile(t, NoPermissions)})

		if err := command.Execute(); errors.Is(err, ErrorFileAccess) != true {
			t.Fatal("Expected file access error")
		}
	})

	t.Run("bad-scan-decode", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", "semgrep", "--config", CopyToTemp(t, TestConfigFilename),
			"--report", CopyToTemp(t, TestReportFilename), CreateMockFile(t, BadDecode)})

		if err := command.Execute(); errors.Is(err, ErrorDecode) != true {
			t.Fatal("Expected file access error")
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

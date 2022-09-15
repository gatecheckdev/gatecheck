package cmd

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/internal"
	"github.com/gatecheckdev/gatecheck/internal/testutil"
	"github.com/gatecheckdev/gatecheck/pkg/exporter/defectDojo"
	"os"
	"path"
	"strings"
	"testing"
)

func TestAddGrypeCmd(t *testing.T) {
	cf, _ := os.Open("../test/gatecheck.yaml")
	gf, _ := os.Open("../test/grype-report.json")
	tempConfigFilename := testutil.ConfigTestCopy(t, cf)
	tempGrypeFilename := testutil.GrypeTestCopy(t, gf)

	// Set up output captureA
	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{})
	command.SetOut(actual)
	command.SetErr(actual)

	t.Run("bad config", func(t *testing.T) {
		command.SetArgs([]string{"report", "add", "grype", tempGrypeFilename})

		if err := command.Execute(); errors.Is(err, internal.ErrorFileNotExists) != true {
			t.Fatal(err)
		}
	})

	t.Run("bad report", func(t *testing.T) {
		tempReportFilename := path.Join(t.TempDir(), "bad-report.json")
		f, _ := os.Create(tempReportFilename)
		_, _ = f.WriteString("{BAD JSON")
		_ = f.Close()

		command.SetArgs([]string{"report", "add", "grype", "--config", tempConfigFilename,
			"--report", tempReportFilename, tempGrypeFilename})

		if err := command.Execute(); errors.Is(err, internal.ErrorDecode) != true {
			t.Error(err)
			t.Fatal("expected decode error")
		}
	})

	t.Run("bad Scan", func(t *testing.T) {
		tempReport := path.Join(t.TempDir(), "gatecheck-report.json")
		tempBadScanFilename := path.Join(t.TempDir(), "bad-scan.json")

		f, _ := os.Open(tempBadScanFilename)
		_, _ = f.WriteString("{BAD SCAN")
		_ = f.Close()

		command.SetArgs([]string{"report", "add", "grype", "--config", tempConfigFilename,
			"--report", tempReport, tempBadScanFilename})

		if err := command.Execute(); errors.Is(err, internal.ErrorDecode) {
			t.Fatal(err)
		}
	})

	t.Run("success", func(t *testing.T) {
		secondReportFilename := path.Join(t.TempDir(), "gatecheck-report.json")

		command.SetArgs([]string{"report", "add", "grype", "--config", tempConfigFilename,
			"--report", secondReportFilename, tempGrypeFilename})

		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestUpdateCmd(t *testing.T) {

	tempReportFilename := path.Join(t.TempDir(), "gatecheck-report.json")
	cf, _ := os.Open("../test/gatecheck.yaml")
	tempConfigFilename := testutil.ConfigTestCopy(t, cf)
	_ = cf.Close()

	// Set up output capture
	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{})
	command.SetOut(actual)
	command.SetErr(actual)

	t.Run("success", func(t *testing.T) {
		command.SetArgs([]string{"report", "update", "--config", tempConfigFilename,
			"--report", tempReportFilename})

		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
		reportBytes, err := os.ReadFile(tempReportFilename)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(string(reportBytes))
	})

	t.Run("Bad config", func(t *testing.T) {
		command.SetArgs([]string{"report", "update", "--config", "nofile.yaml"})

		err := command.Execute()
		if errors.Is(err, internal.ErrorFileNotExists) != true {
			t.Error(err)
			t.Fatal("expected file not exists error")
		}
	})
	t.Run("Update flags", func(t *testing.T) {
		command.SetArgs([]string{"report", "update", "--config", tempConfigFilename, "--report", tempReportFilename,
			"--url", "test.com/pipeline"})

		err := command.Execute()
		if err != nil {
			t.Fatal(err)
		}
		r, err := internal.ReportFromFile(tempReportFilename)
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
	f, err := os.Open("../test/gatecheck-report.json")
	if err != nil {
		t.Fatal(err)
	}
	cf, err := os.Open("../test/gatecheck.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tempReportFilename := testutil.ReportTestCopy(t, f)
	tempConfigFilename := testutil.ConfigTestCopy(t, cf)

	// Set up output capture
	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{})
	command.SetOut(actual)
	command.SetErr(actual)

	command.SetArgs([]string{"report", "print", "--config", tempConfigFilename, "--report", tempReportFilename})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	t.Log(actual.String())

	t.Run("bad config", func(t *testing.T) {
		command.SetArgs([]string{"report", "print", "--config", "somefile.yaml"})

		if err := command.Execute(); errors.Is(err, internal.ErrorFileNotExists) != true {
			t.Fatal(err)
		}
	})
	t.Run("bad report", func(t *testing.T) {
		tempReportFilename := path.Join(t.TempDir(), "bad-report.json")
		f, _ := os.Create(tempReportFilename)
		_, _ = f.WriteString("{BAD JSON")
		_ = f.Close()
		command.SetArgs([]string{"report", "print", "--config", tempConfigFilename, "--report", tempReportFilename})

		if err := command.Execute(); errors.Is(err, internal.ErrorDecode) != true {
			t.Fatal(err)
		}
	})
}

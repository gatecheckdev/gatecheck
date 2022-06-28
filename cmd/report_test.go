package cmd

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/internal"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"io"
	"os"
	"path"
	"strings"
	"testing"
)

func configTestCopy(t *testing.T) string {
	// Create temp copy of the config
	configFile, _ := os.Open("../test/gatecheck.yaml")

	tempConfigFilename := path.Join(t.TempDir(), "gatecheck.yaml")
	tempConfigFile, _ := os.Create(tempConfigFilename)

	if _, err := io.Copy(tempConfigFile, configFile); err != nil {
		t.Fatal(err)
	}
	_ = tempConfigFile.Close()
	_ = configFile.Close()

	return tempConfigFilename
}

func grypeTestCopy(t *testing.T) string {
	// Create a temp copy of the grype report
	grypeFile, _ := os.Open("../test/grype-report.json")
	tempGrypeFilename := path.Join(t.TempDir(), "grype-report.json")

	tempGrypeFile, _ := os.Create(tempGrypeFilename)
	if _, err := io.Copy(tempGrypeFile, grypeFile); err != nil {
		t.Fatal(err)
	}
	_ = tempGrypeFile.Close()
	_ = grypeFile.Close()

	return tempGrypeFilename

}

func reportTestCopy(t *testing.T) string {
	// Create a temp copy of the grype report
	reportFile, _ := os.Open("../test/gatecheck-report.json")
	tempReportFilename := path.Join(t.TempDir(), "gatecheck-report.json")

	tempReportFile, _ := os.Create(tempReportFilename)
	if _, err := io.Copy(tempReportFile, reportFile); err != nil {
		t.Fatal(err)
	}
	_ = tempReportFile.Close()
	_ = reportFile.Close()

	return tempReportFilename
}

func TestAddGrypeCmd(t *testing.T) {

	tempGrypeFilename := grypeTestCopy(t)
	tempConfigFilename := configTestCopy(t)

	// Set up output captureA
	actual := new(bytes.Buffer)
	RootCmd.SetOut(actual)
	RootCmd.SetErr(actual)

	t.Run("bad config", func(t *testing.T) {
		RootCmd.SetArgs([]string{"report", "add", "grype", tempGrypeFilename})

		if err := RootCmd.Execute(); errors.Is(err, internal.ErrorFileNotExists) != true {
			t.Fatal(err)
		}
	})

	t.Run("bad report", func(t *testing.T) {
		tempReportFilename := path.Join(t.TempDir(), "bad-report.json")
		f, _ := os.Create(tempReportFilename)
		_, _ = f.WriteString("{BAD JSON")
		_ = f.Close()

		RootCmd.SetArgs([]string{"report", "add", "grype", "--config", tempConfigFilename,
			"--report", tempReportFilename, tempGrypeFilename})

		if err := RootCmd.Execute(); errors.Is(err, internal.ErrorDecode) != true {
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

		RootCmd.SetArgs([]string{"report", "add", "grype", "--config", tempConfigFilename,
			"--report", tempReport, tempBadScanFilename})

		if err := RootCmd.Execute(); errors.Is(err, internal.ErrorDecode) {
			t.Fatal(err)
		}
	})

	t.Run("success", func(t *testing.T) {
		secondReportFilename := path.Join(t.TempDir(), "gatecheck-report.json")

		RootCmd.SetArgs([]string{"report", "add", "grype", "--config", tempConfigFilename,
			"--report", secondReportFilename, tempGrypeFilename})

		if err := RootCmd.Execute(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestUpdateCmd(t *testing.T) {

	tempReportFilename := path.Join(t.TempDir(), "gatecheck-report.json")
	tempConfigFilename := configTestCopy(t)

	// Set up output capture
	actual := new(bytes.Buffer)
	RootCmd.SetOut(actual)
	RootCmd.SetErr(actual)

	t.Run("success", func(t *testing.T) {
		RootCmd.SetArgs([]string{"report", "update", "--config", tempConfigFilename,
			"--report", tempReportFilename})

		if err := RootCmd.Execute(); err != nil {
			t.Fatal(err)
		}
		reportBytes, err := os.ReadFile(tempReportFilename)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(string(reportBytes))
	})

	t.Run("Bad config", func(t *testing.T) {
		RootCmd.SetArgs([]string{"report", "update", "--config", "nofile.yaml"})

		err := RootCmd.Execute()
		if errors.Is(err, internal.ErrorFileNotExists) != true {
			t.Error(err)
			t.Fatal("expected file not exists error")
		}
	})
	t.Run("Update flags", func(t *testing.T) {
		RootCmd.SetArgs([]string{"report", "update", "--config", tempConfigFilename, "--report", tempReportFilename,
			"--url", "test.com/pipeline"})

		err := RootCmd.Execute()
		if err != nil {
			t.Fatal(err)
		}
		r, err := internal.ReportFromFile(tempReportFilename, *config.NewConfig("Test"))
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
	tempReportFilename := reportTestCopy(t)
	tempConfigFilename := configTestCopy(t)

	// Set up output capture
	actual := new(bytes.Buffer)
	RootCmd.SetOut(actual)
	RootCmd.SetErr(actual)

	RootCmd.SetArgs([]string{"report", "print", "--config", tempConfigFilename,
		"--report", tempReportFilename})
	if err := RootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	t.Log(actual.String())

	t.Run("bad config", func(t *testing.T) {
		RootCmd.SetArgs([]string{"report", "print", "--config", "somefile.yaml"})

		if err := RootCmd.Execute(); errors.Is(err, internal.ErrorFileNotExists) != true {
			t.Fatal(err)
		}
	})
	t.Run("bad report", func(t *testing.T) {
		tempReportFilename := path.Join(t.TempDir(), "bad-report.json")
		f, _ := os.Create(tempReportFilename)
		_, _ = f.WriteString("{BAD JSON")
		_ = f.Close()
		RootCmd.SetArgs([]string{"report", "print", "--config", tempConfigFilename, "--report", tempReportFilename})

		if err := RootCmd.Execute(); errors.Is(err, internal.ErrorDecode) != true {
			t.Fatal(err)
		}
	})
}

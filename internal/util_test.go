package internal_test

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/internal"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"github.com/gatecheckdev/gatecheck/pkg/report"
	"io"
	"os"
	"path"
	"strings"
	"testing"
)

func TestConfigFromFile(t *testing.T) {

	t.Run("Nonexistent File", func(t *testing.T) {
		_, err := internal.ConfigFromFile(path.Join(t.TempDir(), "config.yaml"))

		if errors.Is(err, internal.ErrorFileNotExists) != true {
			t.Error(err)
			t.Fatal("expected error for nonexistent config file")
		}
	})

	t.Run("Bad Permissions", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "config.yaml")
		_, _ = os.Create(fPath)
		_ = os.Chmod(fPath, 0000)

		if _, err := internal.ConfigFromFile(fPath); errors.Is(err, internal.ErrorFileAccess) != true {
			t.Error(err)
			t.Fatal("expected error for bad file permissions")
		}
	})

	t.Run("Bad Config", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "config.yaml")
		f, _ := os.Create(fPath)
		_, err := f.WriteString("BAD YAML")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := internal.ConfigFromFile(fPath); errors.Is(err, internal.ErrorConfig) != true {
			t.Error(err)
			t.Fatal("expected error for bad YAML")
		}
	})

	t.Run("Good Config", func(t *testing.T) {
		configA := config.NewConfig("Test Config")
		fPath := path.Join(t.TempDir(), "gatecheck.yaml")
		f, _ := os.Create(fPath)

		if err := config.NewWriter(f).WriteConfig(configA); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		configB, err := internal.ConfigFromFile(fPath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Compare(configB.ProjectName, "Test Config") != 0 {
			t.Fatalf("expected -> %s got -> %s\n", "Test Config", configB.ProjectName)
		}
	})
}

func TestReportFromFile(t *testing.T) {
	testConfig := config.NewConfig("Test Project")

	t.Run("Nonexistent file", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "gatecheck-report.json")

		loadedReport, err := internal.ReportFromFile(fPath, *testConfig)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Compare(loadedReport.ProjectName, "Test Project") != 0 {
			t.Fatalf("expected -> %s got -> %s\n", "Test Project", loadedReport.ProjectName)
		}
	})

	t.Run("bad permissions", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "gatecheck-report.json")
		f, _ := os.Create(fPath)
		_ = f.Chmod(0000)
		_ = f.Close()
		_, err := internal.ReportFromFile(fPath, *testConfig)
		if errors.Is(err, internal.ErrorFileAccess) != true {
			t.Error(err)
			t.Fatal("expected File Access error")
		}
	})

	t.Run("Bad Report", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "gatecheck-report.json")
		f, _ := os.Create(fPath)
		if _, err := f.WriteString("BAD JSON"); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		_, err := internal.ReportFromFile(fPath, *testConfig)
		if errors.Is(err, internal.ErrorDecode) != true {
			t.Fatal("expected Error for bad JSON")
		}
	})

	t.Run("success, blank", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "gatecheck-report.json")
		loadedReported, err := internal.ReportFromFile(fPath, *testConfig)

		if err != nil {
			t.Fatal(err)
		}
		t.Log(loadedReported.String())

	})

	t.Run("success", func(t *testing.T) {
		// Create temp copy of the report
		reportFile, _ := os.Open("../test/gatecheck-report.json")

		tempReportFilename := path.Join(t.TempDir(), "gatecheck-report.json")
		tempReportFile, _ := os.Create(tempReportFilename)

		if _, err := io.Copy(tempReportFile, reportFile); err != nil {
			t.Fatal(err)
		}

		_ = reportFile.Close()
		_ = tempReportFile.Close()

		loadedReport, err := internal.ReportFromFile(tempReportFilename, *testConfig)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(loadedReport.String())
	})
}

func TestReportToFile(t *testing.T) {

	t.Run("Bad Filename", func(t *testing.T) {
		err := internal.ReportToFile("\000x", report.NewReport("Blank Report"))
		if errors.Is(err, internal.ErrorFileAccess) != true {
			t.Error(err)
			t.Fatal("expected file access error")
		}
	})

	t.Run("success", func(t *testing.T) {
		// Create temp copy of the report
		reportFile, _ := os.Open("../test/gatecheck-report.json")

		tempReportFilename := path.Join(t.TempDir(), "gatecheck-report.json")
		tempReportFile, _ := os.Create(tempReportFilename)

		if _, err := io.Copy(tempReportFile, reportFile); err != nil {
			t.Fatal(err)
		}

		_ = reportFile.Close()
		_ = tempReportFile.Close()

		testConfig := config.NewConfig("Test Project")
		t.Log(testConfig)

		loadedReport, err := internal.ReportFromFile(tempReportFilename, *testConfig)
		if err != nil {
			t.Fatal(err)
		}
		err = internal.ReportToFile(tempReportFilename, loadedReport)
		if err != nil {
			t.Fatal(err)
		}

		reloadedReport, err := internal.ReportFromFile(tempReportFilename, *testConfig)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(reloadedReport)
	})
}

func TestConfigReportFromFiles(t *testing.T) {
	// Create temp copy of the config
	configBytes, _ := os.ReadFile("../test/gatecheck.yaml")

	tempConfigFilename := path.Join(t.TempDir(), "gatecheck.yaml")
	tempConfigFile, _ := os.Create(tempConfigFilename)

	if _, err := io.Copy(tempConfigFile, bytes.NewBuffer(configBytes)); err != nil {
		t.Fatal(err)
	}
	// Create temp copy of the report
	reportBytes, _ := os.ReadFile("../test/gatecheck-report.json")

	tempReportFilename := path.Join(t.TempDir(), "gatecheck-report.json")
	tempReportFile, _ := os.Create(tempReportFilename)

	if _, err := io.Copy(tempReportFile, bytes.NewBuffer(reportBytes)); err != nil {
		t.Fatal(err)
	}

	t.Run("Bad Config", func(t *testing.T) {
		_, _, err := internal.ConfigAndReportFrom("\000x", "\000x")
		if errors.Is(err, internal.ErrorFileNotExists) != true {
			t.Error(err)
			t.Fatal("expected file not exists error")
		}
	})

	t.Run("Bad Report", func(t *testing.T) {
		_, _, err := internal.ConfigAndReportFrom(tempConfigFilename, "\000x")
		if errors.Is(err, internal.ErrorFileAccess) != true {
			t.Error(err)
			t.Fatal("expected file access error")
		}
	})

	t.Run("success", func(t *testing.T) {
		_, _, err := internal.ConfigAndReportFrom(tempConfigFilename, tempReportFilename)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestGrypeScanFromFile(t *testing.T) {
	// Create temp copy of the config
	grypeBytes, _ := os.ReadFile("../test/grype-report.json")

	tempGrypeFilename := path.Join(t.TempDir(), "grype-report.json")
	tempGrypeFile, _ := os.Create(tempGrypeFilename)

	if _, err := io.Copy(tempGrypeFile, bytes.NewBuffer(grypeBytes)); err != nil {
		t.Fatal(err)
	}

	t.Run("Bad file", func(t *testing.T) {
		_, err := internal.GrypeScanFromFile("\000x")
		if errors.Is(err, internal.ErrorFileAccess) != true {
			t.Error(err)
			t.Fatal("expected file access error")
		}
	})
	t.Run("bad json", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "bad.json")
		f, _ := os.Create(fPath)
		_, _ = f.WriteString("BAD JSON")
		_ = f.Close()
		_, err := internal.GrypeScanFromFile(fPath)
		if errors.Is(err, internal.ErrorDecode) != true {
			t.Error(err)
			t.Fatal("expected decode error for bad JSON")
		}
	})
	t.Run("success", func(t *testing.T) {
		scan, err := internal.GrypeScanFromFile(tempGrypeFilename)
		if err != nil {
			t.Fatal(err)
		}
		if len(scan.Matches) < 10 {
			t.Fatal("Match count does not meet expectation")
		}
	})
}

func TestNewFile(t *testing.T) {
	t.Run("Bad file", func(t *testing.T) {

		_, err := internal.NewFile("\000x", "blah")
		if errors.Is(err, internal.ErrorFileAccess) != true {
			t.Error(err)
			t.Fatal("expected file access error")
		}
	})
	t.Run("Directory bad permissions", func(t *testing.T) {
		fPath := t.TempDir()
		if err := os.Chmod(fPath, 0000); err != nil {
			t.Fatal(err)
		}

		_, err := internal.NewFile(fPath, "config.yaml")
		if errors.Is(err, internal.ErrorFileAccess) != true {
			t.Error(err)
			t.Fatal("expected file access error")
		}

	})
	t.Run("Directory", func(t *testing.T) {
		fPath := t.TempDir()
		_, err := internal.NewFile(fPath, "config.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = os.Stat(path.Join(fPath, "config.yaml")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("file exists", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "config.yaml")
		f, _ := os.Create(fPath)
		_ = f.Close()

		_, err := internal.NewFile(fPath, "blah")
		if errors.Is(err, internal.ErrorFileExists) != true {
			t.Fatal("expected file exists error")
		}
	})
	t.Run("file", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "config.yaml")
		_, err := internal.NewFile(fPath, "blah")
		if err != nil {
			t.Fatal(err)
		}
	})
}

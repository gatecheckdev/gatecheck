package cmd

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/internal"
	"github.com/gatecheckdev/gatecheck/internal/testutil"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"github.com/gatecheckdev/gatecheck/pkg/exporter/defectDojo"
	"os"
	"testing"
)

func TestValidateCmd(t *testing.T) {
	actual := new(bytes.Buffer)
	command := NewRootCmd(defectDojo.Exporter{})
	command.SetOut(actual)
	command.SetErr(actual)

	t.Run("bad config", func(t *testing.T) {
		command.SetArgs([]string{"validate"})
		err := command.Execute()
		if errors.Is(err, internal.ErrorFileNotExists) != true {
			t.Error(err)
			t.Fatal("Expected file not exists error")
		}
	})

	t.Run("fail validation", func(t *testing.T) {
		cf, _ := os.Open("../test/gatecheck.yaml")
		rf, _ := os.Open("../test/gatecheck-report.json")
		tempConfigFilename := testutil.ConfigTestCopy(t, cf)
		tempReportFilename := testutil.ReportTestCopy(t, rf)

		command.SetArgs([]string{"validate", "-c", tempConfigFilename, "-r", tempReportFilename})

		err := command.Execute()

		if errors.Is(err, internal.ErrorValidation) != true {
			t.Error(err)
			t.Fatal("expected validation error")
		}
	})
	t.Run("audit", func(t *testing.T) {
		cf, _ := os.Open("../test/gatecheck.yaml")
		rf, _ := os.Open("../test/gatecheck-report.json")
		tempConfigFilename := testutil.ConfigTestCopy(t, cf)
		tempReportFilename := testutil.ReportTestCopy(t, rf)

		command.SetArgs([]string{"validate", "-c", tempConfigFilename, "-r", tempReportFilename, "-a"})

		err := command.Execute()

		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("bad report", func(t *testing.T) {
		cf, _ := os.Open("../test/gatecheck.yaml")
		rf, _ := os.Open("../test/gatecheck-report.json")
		tempConfigFilename := testutil.ConfigTestCopy(t, cf)
		tempReportFilename := testutil.ReportTestCopy(t, rf)

		c := config.NewConfig("Test Project")
		f, err := os.Create(tempConfigFilename)
		if err != nil {
			t.Fatal(err)
		}
		if err := config.NewWriter(f).WriteConfig(c); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		command.SetArgs([]string{"validate", "-c", tempConfigFilename, "-r", tempReportFilename})

		if err = command.Execute(); err != nil {
			t.Fatal(err)
		}

	})
	t.Run("successful validation", func(t *testing.T) {
		cf, _ := os.Open("../test/gatecheck.yaml")
		tempConfigFilename := testutil.ConfigTestCopy(t, cf)

		command.SetArgs([]string{"validate", "-c", tempConfigFilename, "-r", "\000x"})

		err := command.Execute()

		if errors.Is(err, internal.ErrorFileAccess) != true {
			t.Error(err)
			t.Fatal("expected file access error")
		}
	})

}

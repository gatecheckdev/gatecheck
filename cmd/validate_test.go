package cmd

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/internal"
	"github.com/gatecheckdev/gatecheck/internal/testutil"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"os"
	"testing"
)

func TestValidateCmd(t *testing.T) {
	actual := new(bytes.Buffer)
	RootCmd.SetOut(actual)
	RootCmd.SetErr(actual)

	t.Run("bad config", func(t *testing.T) {
		RootCmd.SetArgs([]string{"validate"})
		err := RootCmd.Execute()
		if errors.Is(err, internal.ErrorFileNotExists) != true {
			t.Error(err)
			t.Fatal("Expected file not exists error")
		}
	})

	t.Run("fail validation", func(t *testing.T) {
		tempConfigFilename := testutil.ConfigTestCopy(t)
		tempReportFilename := testutil.ReportTestCopy(t)

		RootCmd.SetArgs([]string{"validate", "-c", tempConfigFilename, "-r", tempReportFilename})

		err := RootCmd.Execute()

		if errors.Is(err, internal.ErrorValidation) != true {
			t.Error(err)
			t.Fatal("expected validation error")
		}
	})
	t.Run("audit", func(t *testing.T) {
		tempConfigFilename := testutil.ConfigTestCopy(t)
		tempReportFilename := testutil.ReportTestCopy(t)

		RootCmd.SetArgs([]string{"validate", "-c", tempConfigFilename, "-r", tempReportFilename, "-a"})

		err := RootCmd.Execute()

		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("bad report", func(t *testing.T) {
		tempConfigFilename := testutil.ConfigTestCopy(t)
		tempReportFilename := testutil.ReportTestCopy(t)

		c := config.NewConfig("Test Project")
		f, err := os.Create(tempConfigFilename)
		if err != nil {
			t.Fatal(err)
		}
		if err := config.NewWriter(f).WriteConfig(c); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		RootCmd.SetArgs([]string{"validate", "-c", tempConfigFilename, "-r", tempReportFilename})

		if err = RootCmd.Execute(); err != nil {
			t.Fatal(err)
		}

	})
	t.Run("successful validation", func(t *testing.T) {
		tempConfigFilename := testutil.ConfigTestCopy(t)

		RootCmd.SetArgs([]string{"validate", "-c", tempConfigFilename, "-r", "\000x"})

		err := RootCmd.Execute()

		if errors.Is(err, internal.ErrorFileAccess) != true {
			t.Error(err)
			t.Fatal("expected file access error")
		}
	})

}

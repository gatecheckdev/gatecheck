package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

var (
	semgrepTestReport  = "../test/semgrep-sast-report.json"
	gitleaksTestReport = "../test/gitleaks-report.json"
	grypeTestReport    = "../test/grype-report.json"
	epssTestCSV        = "../test/epss_scores-2023-06-01.csv"
	kevTestFile        = "../test/known_exploited_vulnerabilities.json"
)

func Test_RootCommand(t *testing.T) {
	t.Parallel()
	t.Run("logo", func(t *testing.T) {
		out, err := Execute("", CLIConfig{AutoDecoderTimeout: time.Nanosecond})
		if err != nil {
			t.Fatal(err)
		}
		if len(out) < 100 {
			t.FailNow()
		}
	})

	t.Run("version-flag", func(t *testing.T) {
		version := "TEST.VERSION.32"
		out, err := Execute("--version", CLIConfig{Version: version})
		if err != nil {
			t.Fatal("Error:", err, "Output:", out)
		}
		if strings.Contains(out, version) == false {
			t.Fatal(version, "Not Contained in", out)
		}
	})

	t.Run("version-cmd", func(t *testing.T) {
		version := "TEST.VERSION.32"
		out, err := Execute("version", CLIConfig{Version: version})
		if err != nil {
			t.Fatal("Error:", err, "Output:", out)
		}
		if strings.Contains(out, version) == false {
			t.Fatal(version, "Not Contained in", out)
		}
	})
}

func Test_InitCommand(t *testing.T) {
	out, err := Execute("config init", CLIConfig{AutoDecoderTimeout: time.Nanosecond})
	if err != nil {
		t.FailNow()
	}
	if strings.Contains(out, "grype") == false {
		t.FailNow()
	}
	t.Log(out)
}

// Helper Functions
func Execute(command string, config CLIConfig) (commandOutput string, commandError error) {
	buf := new(bytes.Buffer)

	cmd := NewRootCommand(config)
	cmd.SetOut(buf)
	cmd.SetArgs(strings.Split(command, " "))
	cmd.SilenceUsage = true
	err := cmd.Execute()

	return buf.String(), err
}

func MustOpen(filename string, failFunc func(args ...any)) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		failFunc(err)
		return nil
	}
	return f
}

package cmd

import (
	"bytes"
	"os"
	"path"
	"strings"
	"testing"
)

var (
	semgrepTestReport   = "../../test/semgrep-sast-report.json"
	gitleaksTestReport  = "../../test/gitleaks-report.json"
	grypeTestReport     = "../../test/grype-report.json"
	cyclonedxTestReport = "../../test/cyclonedx-grype-sbom.json"
	epssTestCSV         = "../../test/epss_scores-2023-06-01.csv"
)

func Test_RootCommand(t *testing.T) {
	t.Parallel()
	t.Run("logo", func(t *testing.T) {
		out, err := Execute("", CLIConfig{})
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
	out, err := Execute("config init", CLIConfig{})
	if err != nil {
		t.FailNow()
	}
	if strings.Contains(out, "grype") == false {
		t.FailNow()
	}
	t.Log(out)
}

func Test_InfoCommand(t *testing.T) {
	_, err := Execute("config info", CLIConfig{
		ConfigFileUsed: "mockfile",
		ConfigMap:      map[string]any{"gatecheck_mock_key": "mock value"},
		ConfigPath:     "mock.path",
	})
	if err != nil {
		t.FailNow()
	}
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

func MustOpen(filename string, t *testing.T) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
		return nil
	}
	return f
}

func fileWithBadPermissions(t *testing.T) (filename string) {
	n := path.Join(t.TempDir(), "bad-file")
	f, err := os.Create(n)
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Chmod(0o000); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	return n
}

func fileWithBadJSON(t *testing.T) (filename string) {
	n := path.Join(t.TempDir(), "bad-file.json")

	if err := os.WriteFile(n, []byte("{{"), 0o664); err != nil {
		t.Fatal(err)
	}

	return n
}

func MustCreate(filename string, t *testing.T) *os.File {
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func MustRead(filename string, t *testing.T) []byte {
	b, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

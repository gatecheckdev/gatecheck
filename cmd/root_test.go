package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

func Test_RootCommand(t *testing.T) {
	t.Parallel()
	t.Run("logo", func(t *testing.T) {
		out, err := Run("")
		if err != nil {
			t.Fatal(err)
		}
		if len(out) < 100 {
			t.FailNow()
		}
	})

	t.Run("version", func(t *testing.T) {
		version := "TEST.VERSION.32"
		out, err := RunWithConfig("--version", CLIConfig{Version: version})
		if err != nil {
			t.Fatal("Error:", err, "Output:", out)
		}
		if strings.Contains(out, version) == false {
			t.Fatal(version, "Not Contained in", out)
		}
	})
}

func Test_PrintCommand(t *testing.T) {
	config := CLIConfig{AutoDecoderTimeout: time.Second * 2}
	t.Parallel()
	t.Run("semgrep", func(t *testing.T) {
		f := GetTempFile(t, SemgrepReportClone)
		out, err := RunWithConfig("print "+f.Name(), config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "WARNING") == false {
			t.Fatal("'WARNING' not contained in", out)
		}
	})
	t.Run("grype", func(t *testing.T) {
		f := GetTempFile(t, GrypeReportClone)
		out, err := RunWithConfig("print "+f.Name(), config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "debian") == false {
			t.Fatal("'debian' not contained in", out)
		}
	})
	t.Run("gitleaks", func(t *testing.T) {
		f := GetTempFile(t, GitleaksReportClone)
		out, err := RunWithConfig("print "+f.Name(), config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "jwt") == false {
			t.Fatal("'jwt' not contained in", out)
		}
		t.Log(out)
	})
	t.Run("multiple-files-and-piped-input", func(t *testing.T) {
		f1 := GetTempFile(t, GrypeReportClone)
		f2 := GetTempFile(t, SemgrepReportClone)
		f3 := GetTempFile(t, GitleaksReportClone)
		config := CLIConfig{AutoDecoderTimeout: time.Second * 2, PipedInput: f3}
		commandString := fmt.Sprintf("print %s %s", f1.Name(), f2.Name())
		out, err := RunWithConfig(commandString, config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "debian") == false {
			t.Fatal("'debian' not contained in", out)
		}
		if strings.Contains(out, "WARNING") == false {
			t.Fatal("'WARNING' not contained in", out)
		}
		if strings.Contains(out, "jwt") == false {
			t.Fatal("'jwt' not contained in", out)
		}
		t.Log(out)
	})
}

func Test_InitCommand(t *testing.T) {
	out, err := Run("config init")
	if err != nil {
		t.FailNow()
	}
	if strings.Contains(out, "grype") == false {
		t.FailNow()
	}
	t.Log(out)
}

// Helper Functions
func Run(command string) (commandOutput string, commandError error) {
	return RunWithConfig(command, CLIConfig{AutoDecoderTimeout: time.Nanosecond})
}

func RunWithConfig(command string, config CLIConfig) (commandOutput string, commandError error) {
	buf := new(bytes.Buffer)

	cmd := NewRootCommand(config)
	cmd.SetOut(buf)
	cmd.SetArgs(strings.Split(command, " "))
	err := cmd.Execute()

	return buf.String(), err
}

type testFileType int

const (
	SemgrepReportClone testFileType = iota
	GrypeReportClone
	GitleaksReportClone
)

type TempMaker interface {
	TempDir() string
}

func GetTempFile(t TempMaker, fileType testFileType) *os.File {
	var targetFile *os.File
	var filename string

	switch fileType {
	case SemgrepReportClone:
		targetFile, _ = os.Open("../test/semgrep-sast-report.json")
		filename = "semgrep-sast-report.json"
	case GrypeReportClone:
		targetFile, _ = os.Open("../test/grype-report.json")
		filename = "grype-report.json"
	case GitleaksReportClone:
		targetFile, _ = os.Open("../test/gitleaks-report.json")
		filename = "gitleaks-report.json"
	default:
		targetFile = nil
	}
	f, err := os.Create(path.Join(t.TempDir(), filename))
	if err != nil {
		panic(err)
	}
	_, err = io.Copy(f, targetFile)
	if err != nil {
		panic(err)
	}
	if _, err := f.Seek(io.SeekStart, 0); err != nil {
		panic(err)
	}

	return f
}

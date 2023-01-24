package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

func TestParseAndFPrint(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		semgrepFile := MustOpen(semgrepTestReport, t.Fatal)
		grypeFile := MustOpen(grypeTestReport, t.Fatal)
		gitleaksFile := MustOpen(gitleaksTestReport, t.Fatal)
		expected := []string{"WARNING", "debian", "jwt"}
		for i, file := range []io.Reader{semgrepFile, grypeFile, gitleaksFile} {
			outputBuf := new(bytes.Buffer)
			if err := ParseAndFPrint(file, outputBuf, time.Second*4); err != nil {
				t.Fatal(err)
			}

			if strings.Contains(outputBuf.String(), expected[i]) != true {
				t.Log(outputBuf)
				t.Fatalf("Test Number %d Failed assertion", i)
			}
		}
	})

	t.Run("timeout", func(t *testing.T) {
		outputBuf := new(bytes.Buffer)
		grypeFile := MustOpen(grypeTestReport, t.Fatal)
		err := ParseAndFPrint(grypeFile, outputBuf, time.Nanosecond*1)
		if errors.Is(err, context.Canceled) != true {
			t.Fatal(err)
		}
	})

}

func Test_PrintCommand(t *testing.T) {
	config := CLIConfig{AutoDecoderTimeout: time.Second * 2}
	t.Parallel()

	t.Run("semgrep", func(t *testing.T) {
		f := MustOpen(semgrepTestReport, t.Fatal)
		out, err := Execute("print "+f.Name(), config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "WARNING") == false {
			t.Fatal("'WARNING' not contained in", out)
		}
	})
	t.Run("grype", func(t *testing.T) {
		f := MustOpen(grypeTestReport, t.Fatal)
		out, err := Execute("print "+f.Name(), config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "debian") == false {
			t.Fatal("'debian' not contained in", out)
		}
	})
	t.Run("gitleaks", func(t *testing.T) {
		f := MustOpen(gitleaksTestReport, t.Fatal)
		out, err := Execute("print "+f.Name(), config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "jwt") == false {
			t.Fatal("'jwt' not contained in", out)
		}
		t.Log(out)
	})

	t.Run("multiple-files-and-piped-input", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			f1 := MustOpen(grypeTestReport, t.Fatal)
			f2 := MustOpen(semgrepTestReport, t.Fatal)
			f3 := MustOpen(gitleaksTestReport, t.Fatal)
			config := CLIConfig{AutoDecoderTimeout: time.Second * 2, PipedInput: f3}
			commandString := fmt.Sprintf("print %s %s", f1.Name(), f2.Name())
			out, err := Execute(commandString, config)
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
	})

	t.Run("bad-piped-file", func(t *testing.T) {
		f := MustOpen(grypeTestReport, t.Fatal)
		config := CLIConfig{AutoDecoderTimeout: time.Nanosecond, PipedInput: f}
		if _, err := Execute("print", config); errors.Is(err, ErrorEncoding) != true {
			t.Fatal("Expected error for bad file, got", err)
		}
	})

	t.Run("bad-file", func(t *testing.T) {
		badFile := fileWithBadPermissions(t)
		config := CLIConfig{AutoDecoderTimeout: time.Second * 2}

		if _, err := Execute("print "+badFile, config); errors.Is(err, ErrorFileAccess) != true {
			t.Fatal("Expected error for bad file, got", err)
		}
	})

	t.Run("decode-error", func(t *testing.T) {

		config := CLIConfig{AutoDecoderTimeout: time.Nanosecond}

		if _, err := Execute("print "+fileWithBadJSON(t), config); errors.Is(err, ErrorEncoding) != true {
			t.Fatal("Expected encoding error for bad file, got", err)
		}
	})

	t.Run("unsupported-file", func(t *testing.T) {
		b := make([]byte, 1000)
		randomFile := path.Join(t.TempDir(), "random.file")
		if err := os.WriteFile(randomFile, b, 0664); err != nil {
			t.Fatal(err)
		}

		config := CLIConfig{AutoDecoderTimeout: time.Second * 3}

		if _, err := Execute("print "+randomFile, config); err != nil {
			t.Fatal(err)
		}
	})

}

func fileWithBadPermissions(t *testing.T) (filename string) {
	n := path.Join(t.TempDir(), "bad-file")
	f, err := os.Create(n)
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Chmod(0000); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	return n
}

func fileWithBadJSON(t *testing.T) (filename string) {
	n := path.Join(t.TempDir(), "bad-file.json")

	if err := os.WriteFile(n, []byte("{{"), 0664); err != nil {
		t.Fatal(err)
	}

	return n
}

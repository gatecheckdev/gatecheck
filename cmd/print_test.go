package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseAndFPrint(t *testing.T) {
	semgrepFile, _ := os.Open("../test/semgrep-sast-report.json")
	grypeFile, _ := os.Open("../test/grype-report.json")
	gitleaksFile, _ := os.Open("../test/gitleaks-report.json")
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
}

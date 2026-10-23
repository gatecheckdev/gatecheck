package bootstrap

import (
	"os"
	"strings"
	"testing"
)

func TestDocsMentionPins(t *testing.T) {
	files := []string{
		"../../docs/bootstrap.md",
		"../../docs/agent-guide.md",
	}
	needles := []string{
		GrypeVersion,
		SyftVersion,
		GitleaksVersion,
		SemgrepVersion,
		TrivyVersion,
		OSVScannerVersion,
		"GATECHECK_HOME",
		"osemgrep",
		"--experimental",
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := string(body)
		for _, needle := range needles {
			if !strings.Contains(text, needle) {
				t.Errorf("%s missing %q", file, needle)
			}
		}
	}
}

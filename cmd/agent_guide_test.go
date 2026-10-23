package cmd

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/docs"
	"github.com/spf13/cobra"
)

func TestAgentGuideCommand(t *testing.T) {
	needles := []string{
		"gatecheck validate --config",
		"config init",
		"--input-type",
		"0.8",
		"GATECHECK_CONFIG_FILENAME",
		"bundle create",
		"download epss",
	}

	for _, args := range [][]string{{"agent-guide"}, {"llm"}} {
		root := &cobra.Command{Use: "gatecheck"}
		root.AddCommand(newAgentGuideCommand())
		var buf bytes.Buffer
		root.SetOut(&buf)
		root.SetErr(io.Discard)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if buf.String() != docs.AgentGuide {
			t.Fatalf("%v: output is not docs/agent-guide.md", args)
		}
		for _, needle := range needles {
			if !strings.Contains(buf.String(), needle) {
				t.Errorf("%v: missing %q", args, needle)
			}
		}
	}
}

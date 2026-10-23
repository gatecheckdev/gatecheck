package cmd

import (
	"io"

	"github.com/gatecheckdev/gatecheck/docs"
	"github.com/spf13/cobra"
)

func newAgentGuideCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "agent-guide",
		Aliases: []string{"llm"},
		Short:   "print a markdown guide for agents that run gatecheck",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := io.WriteString(cmd.OutOrStdout(), docs.AgentGuide)
			return err
		},
	}
}

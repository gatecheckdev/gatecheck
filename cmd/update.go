package cmd

import (
	"github.com/gatecheckdev/gatecheck/pkg/update"
	"github.com/spf13/cobra"
)

// updateAPIBase and updateExecutable are test seams. They are not user settings.
var (
	updateAPIBase    string
	updateExecutable string
)

func newUpdateCommand() *cobra.Command {
	var (
		check   bool
		version string
		yes     bool
	)

	command := &cobra.Command{
		Use:     "update",
		Aliases: []string{"self-update", "upgrade"},
		Short:   "Replace this binary with a GitHub release",
		Args:    cobra.NoArgs,
		Long: `Replace this binary with a gatecheck release from GitHub.

The latest release is used unless --version is set. The downloaded archive
is checked against checksums.txt before the binary is replaced. A dev build
with no release version refuses unless --version is set.

When stdin is a terminal, gatecheck asks before replacing the binary.
Otherwise the update runs only when --yes is set. --check prints the current
and latest versions and does not download.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return update.Run(cmd.Context(), update.Options{
				CurrentVersion: ApplicationMetadata.CLIVersion,
				TargetVersion:  version,
				CheckOnly:      check,
				AssumeYes:      yes,
				Stdin:          cmd.InOrStdin(),
				Stdout:         cmd.OutOrStdout(),
				Stderr:         cmd.ErrOrStderr(),
				Executable:     updateExecutable,
				APIBase:        updateAPIBase,
			})
		},
	}
	command.Flags().BoolVar(&check, "check", false, "print the current and latest versions and do not download")
	command.Flags().StringVar(&version, "version", "", "install this release (vX.Y.Z) instead of the latest")
	command.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return command
}

func addCommandOnce(root *cobra.Command, command *cobra.Command) {
	for _, existing := range root.Commands() {
		if existing.Name() == command.Name() {
			return
		}
	}
	root.AddCommand(command)
}

var updateCmd = newUpdateCommand()

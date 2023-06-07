package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	ErrorFileAccess     = errors.New("file access")
	ErrorEncoding       = errors.New("encoding")
	ErrorValidation     = errors.New("validation")
	ErrorAPI            = errors.New("request API")
	ErrorUserInput      = errors.New("user error")
	GlobalVerboseOutput = false
)

type DDExportService interface {
	Export(context.Context, io.Reader, defectdojo.EngagementQuery, defectdojo.ScanType) error
}

type EPSSService interface {
	WriteCSV(w io.Writer, url string) (int64, error)
	WriteEPSS([]epss.CVE) error
}

type AWSExportService interface {
	Export(context.Context, io.Reader, string) error
}

type CLIConfig struct {
	AutoDecoderTimeout time.Duration
	Version            string
	PipedInput         *os.File
	DefaultReport      string
	EPSSService        EPSSService
	DDExportService    DDExportService
	DDEngagement       defectdojo.EngagementQuery
	DDExportTimeout    time.Duration
	AWSExportService   AWSExportService
	AWSExportTimeout   time.Duration
}

func NewRootCommand(config CLIConfig) *cobra.Command {
	command := &cobra.Command{
		Use:     "gatecheck",
		Version: config.Version,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Printf(GatecheckLogo)
			return nil
		},
	}

	// Global Flags
	command.PersistentFlags().BoolVarP(&GlobalVerboseOutput, "verbose", "v", false, "Verbose debug output")

	// Commands
	command.AddCommand(NewVersionCmd(config.Version))
	command.AddCommand(NewPrintCommand(config.AutoDecoderTimeout, config.PipedInput))
	command.AddCommand(NewConfigCmd(), NewBundleCmd())
	command.AddCommand(NewValidateCmd(config.AutoDecoderTimeout))
	command.AddCommand(NewEPSSCmd(config.EPSSService))
	command.AddCommand(
		NewExportCmd(
			config.DDExportService,
			config.DDExportTimeout,
			config.DDEngagement,
			config.AWSExportService,
			config.AWSExportTimeout,
		),
	)

	return command
}

func NewVersionCmd(version string) *cobra.Command {
	command := &cobra.Command{
		Use: "version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Printf(GatecheckLogo)
			cmd.Println("A utility for aggregating, validating, and exporting vulnerability reports")
			cmd.Println("Version:", version)
			return nil
		},
	}

	return command
}

func NewConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Creates a new configuration file",
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "prints a new configuration file.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return yaml.NewEncoder(cmd.OutOrStdout()).Encode(artifact.NewConfig())
		},
	}

	cmd.AddCommand(initCmd)

	return cmd
}

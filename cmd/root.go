package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/export/aws"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
)

var ErrorFileAccess = errors.New("file access")
var ErrorEncoding = errors.New("encoding")
var ErrorValidation = errors.New("validation")
var ErrorAPI = errors.New("request API")

type DDExportService interface {
	Export(context.Context, io.Reader, defectdojo.EngagementQuery, defectdojo.ScanType) error
}

type EPSSService interface {
	Get([]epss.CVE) ([]epss.Data, error)
}

type AWSExportService interface {
	Export(context.Context, io.Reader, aws.Upload) error
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
	AWSUpload          aws.Upload
}

func NewRootCommand(config CLIConfig) *cobra.Command {
	var command = &cobra.Command{
		Use:     "gatecheck",
		Short:   "A utility for aggregating, validating, and exporting vulnerability reports from other tools",
		Version: config.Version,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Printf(GatecheckLogo)
			return nil
		},
	}
	command.InitDefaultVersionFlag()

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
			config.AWSUpload,
		),
	)
	return command
}

func NewConfigCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "config",
		Short: "Creates a new configuration file",
	}

	var initCmd = &cobra.Command{
		Use:   "init",
		Short: "prints a new configuration file.",
		RunE: func(cmd *cobra.Command, _ []string) error {

			return yaml.NewEncoder(cmd.OutOrStdout()).Encode(artifact.NewConfig())
		},
	}

	cmd.AddCommand(initCmd)

	return cmd
}

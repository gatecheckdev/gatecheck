package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	ErrorFileAccess     = errors.New("File Access Failure")
	ErrorEncoding       = errors.New("Encoding Failure")
	ErrorValidation     = errors.New("Validation Failure")
	ErrorAPI            = errors.New("API Failure")
	ErrorUserInput      = errors.New("User Input Failure")
	GlobalVerboseOutput = false
)

type DDExportService interface {
	Export(context.Context, io.Reader, defectdojo.EngagementQuery, defectdojo.ScanType) error
}

type AWSExportService interface {
	Export(context.Context, io.Reader, string) error
}

type AsyncDecoder interface {
	io.Writer
	Decode() (any, error)
	DecodeFrom(r io.Reader) (any, error)
	FileType() string
	Reset()
}

type CLIConfig struct {
	Version             string
	PipedInput          *os.File
	EPSSDownloadAgent   io.Reader
	KEVDownloadAgent    io.Reader
	DDExportService     DDExportService
	DDEngagement        defectdojo.EngagementQuery
	DDExportTimeout     time.Duration
	AWSExportService    AWSExportService
	AWSExportTimeout    time.Duration
	NewAsyncDecoderFunc func() AsyncDecoder
	ConfigMap           map[string]any
	ConfigFileUsed      string
	ConfigPath          string
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
	command.AddCommand(NewPrintCommand(config.PipedInput, config.NewAsyncDecoderFunc))
	command.AddCommand(NewConfigCmd(config.ConfigMap, config.ConfigFileUsed, config.ConfigPath))
	command.AddCommand(NewValidateCmd(config.NewAsyncDecoderFunc, config.KEVDownloadAgent, config.EPSSDownloadAgent))
	command.AddCommand(NewEPSSCmd(config.EPSSDownloadAgent))
	command.AddCommand(
		NewExportCmd(
			config.DDExportService,
			config.DDExportTimeout,
			config.NewAsyncDecoderFunc,
			config.DDEngagement,
			config.AWSExportService,
			config.AWSExportTimeout,
		),
	)
	command.AddCommand(NewBundleCmd(config.NewAsyncDecoderFunc))

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

func NewConfigCmd(configMap map[string]any, configFileUsed string, configPath string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Creates a new configuration file",
	}

	infoCmd := &cobra.Command{
		Use:   "info",
		Short: "Print configuration settings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Println("Config file used:", configFileUsed)
			fmt.Println("Config file search paths:", configPath)
			for key, value := range configMap {
				fmt.Printf("%s: '%s'\n", strings.ToUpper(key), value)
			}
			return nil
		},
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "prints a new configuration file.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			configMap := map[string]any{
				grype.ConfigFieldName: grype.Config{
					AllowList:          []grype.ListItem{{Id: "example allow id", Reason: "example reason"}},
					DenyList:           []grype.ListItem{{Id: "example deny id", Reason: "example reason"}},
					EPSSAllowThreshold: 1,
					EPSSDenyThreshold:  1,
					Critical:           -1,
					High:               -1,
					Medium:             -1,
					Low:                -1,
					Negligible:         -1,
					Unknown:            -1,
				},
				semgrep.ConfigFieldName: semgrep.Config{
					Info:    -1,
					Warning: -1,
					Error:   -1,
				},
				gitleaks.ConfigFieldName: gitleaks.Config{
					SecretsAllowed: true,
				},
				cyclonedx.ConfigFieldName: cyclonedx.Config{
					AllowList: []cyclonedx.ListItem{{Id: "example allow id", Reason: "example reason"}},
					DenyList:  []cyclonedx.ListItem{{Id: "example deny id", Reason: "example reason"}},
					Required:  false,
					Critical:  -1,
					High:      -1,
					Medium:    -1,
					Low:       -1,
					Info:      -1,
					None:      -1,
					Unknown:   -1,
				},
			}
			enc := yaml.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent(2)
			return yaml.NewEncoder(cmd.OutOrStdout()).Encode(configMap)
		},
	}

	cmd.AddCommand(initCmd, infoCmd)

	return cmd
}

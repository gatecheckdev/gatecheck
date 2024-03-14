// Package main executes the CLI for gatecheck
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/gatecheckdev/gatecheck/cmd/v0"
	cmdV1 "github.com/gatecheckdev/gatecheck/cmd/v1"
	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/export/aws"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/gatecheckdev/gatecheck/pkg/kev"
)

const (
	exitSystemFail     int = -1
	exitOk             int = 0
	exitFileAccessFail int = 2
	exitValidationFail     = 1
)

// GatecheckVersion see CHANGELOG.md
const GatecheckVersion = "v0.3.0"

// all variables here are provided as build-time arguments, with clear default values
var (
	cliVersion     = "[Not Provided]"
	buildDate      = "[Not Provided]"
	gitCommit      = "[Not Provided]"
	gitDescription = "[Not Provided]"
)

func main() {
	ffCLIV1Enabled := os.Getenv("GATECHECK_FF_CLI_V1_ENABLED")

	switch ffCLIV1Enabled {
	case "1":
		runV1()
	default:
		runV0()
	}
}

func runV1() {
	cmdV1.ApplicationMetadata = gatecheck.ApplicationMetadata{
		CLIVersion:     cliVersion,
		GitCommit:      gitCommit,
		BuildDate:      buildDate,
		GitDescription: gitDescription,
		Platform:       fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		GoVersion:      runtime.Version(),
		Compiler:       runtime.Compiler,
	}

	// Colorized logging output for the CLI
	logHandler := tint.NewHandler(os.Stderr, &tint.Options{Level: cmdV1.LogLeveler, TimeFormat: time.TimeOnly})
	slog.SetDefault(slog.New(logHandler))

	command := cmdV1.NewGatecheckCommand()

	slog.Info("Gatecheck CLI v1 is enabled")
	err := command.Execute()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func runV0() {
	viper.SetConfigType("env")
	viper.SetConfigName("settings")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.config/gatecheck/")

	viper.SetDefault("GATECHECK_KEV_URL", kev.DefaultBaseURL)
	viper.SetDefault("GATECHECK_EPSS_URL", epss.DefaultBaseURL)
	viper.SetDefault("GATECHECK_DD_API_KEY", "")
	viper.SetDefault("GATECHECK_DD_API_URL", "")
	viper.SetDefault("GATECHECK_DD_PRODUCT_TYPE", "")
	viper.SetDefault("GATECHECK_DD_PRODUCT", "")
	viper.SetDefault("GATECHECK_DD_ENGAGEMENT", "")
	viper.SetDefault("GATECHECK_DD_BRANCH_TAG", "")
	viper.SetDefault("GATECHECK_DD_SOURCE_URL", "")
	viper.SetDefault("GATECHECK_DD_COMMIT_HASH", "")
	viper.SetDefault("GATECHECK_DD_DEDUPLICATION_ON_ENGAGEMENT", false)
	viper.SetDefault("GATECHECK_DD_CLOSE_OLD_FINDINGS", false)
	viper.SetDefault("GATECHECK_DD_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE", false)
	viper.SetDefault("GATECHECK_DD_CREATE_FINDING_GROUPS_FOR_ALL_FINDINGS", true)
	viper.SetDefault("GATECHECK_DD_ENABLE_SIMPLE_RISK_ACCEPTANCE", false)
	viper.SetDefault("GATECHECK_AWS_BUCKET", "")
	viper.SetDefault("GATECHECK_AWS_PROFILE", "")
	// **Required:** Override the active (findings) setting/status from the tool
	// Note: `false` will import all findings as `Inactive`
	viper.SetDefault("GATECHECK_DD_IMPORT_SCAN_ACTIVE", true)
	// **Required:** Override the verified (findings) setting/status from the tool
	viper.SetDefault("GATECHECK_DD_IMPORT_SCAN_VERIFIED", false)
	// **Required (as of 2023-10-13):** Add tags that help describe this scan
	viper.SetDefault("GATECHECK_DD_TAGS", "")
	// Choose an option to automatically group new findings by the chosen option
	viper.SetDefault("GATECHECK_DD_GROUP_BY", "")
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			slog.Error("viper configuration error", "err", err)
			os.Exit(exitSystemFail)
		}
	}

	dojoKey := viper.GetString("GATECHECK_DD_API_KEY")
	dojoURL := viper.GetString("GATECHECK_DD_API_URL")

	dojoCloseOldFindings := viper.GetBool("GATECHECK_DD_CLOSE_OLD_FINDINGS")
	dojoCloseOldFindingsProductScope := viper.GetBool("GATECHECK_DD_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE")
	dojoCreateFindingGroupsForAllFindings := viper.GetBool("GATECHECK_DD_CREATE_FINDING_GROUPS_FOR_ALL_FINDINGS")
	dojoImportScanActive := viper.GetBool("GATECHECK_DD_IMPORT_SCAN_ACTIVE")
	dojoImportScanVerified := viper.GetBool("GATECHECK_DD_IMPORT_SCAN_VERIFIED")
	dojoGroupBy := viper.GetString("GATECHECK_DD_GROUP_BY")

	ddEngagement := defectdojo.EngagementQuery{
		ProductTypeName:            viper.GetString("GATECHECK_DD_PRODUCT_TYPE"),
		ProductName:                viper.GetString("GATECHECK_DD_PRODUCT"),
		Name:                       viper.GetString("GATECHECK_DD_ENGAGEMENT"),
		Duration:                   time.Hour * 48,
		BranchTag:                  viper.GetString("GATECHECK_DD_BRANCH_TAG"),
		SourceURL:                  viper.GetString("GATECHECK_DD_SOURCE_URL"),
		CommitHash:                 viper.GetString("GATECHECK_DD_COMMIT_HASH"),
		Tags:                       strings.Split(viper.GetString("GATECHECK_DD_TAGS"), ","),
		DeduplicationOnEngagement:  viper.GetBool("GATECHECK_DD_DEDUPLICATION_ON_ENGAGEMENT"),
		EnableSimpleRiskAcceptance: viper.GetBool("GATECHECK_DD_ENABLE_SIMPLE_RISK_ACCEPTANCE"),
	}

	dojoService := defectdojo.NewService(http.DefaultClient, dojoKey, dojoURL, dojoCloseOldFindings, dojoCloseOldFindingsProductScope, dojoCreateFindingGroupsForAllFindings, dojoImportScanActive, dojoImportScanVerified, dojoGroupBy)

	awsBucket := viper.GetString("GATECHECK_AWS_BUCKET")
	awsProfile := viper.GetString("GATECHECK_AWS_PROFILE")

	cfg, _ := config.LoadDefaultConfig(context.Background(),
		config.WithSharedConfigProfile(awsProfile),
	)

	awsService := aws.NewService(awsBucket, cfg)

	var pipedFile *os.File
	if PipeInput() {
		pipedFile = os.Stdin
	}

	viper.AddConfigPath("$HOME/.config/gatecheck/")
	viper.AddConfigPath(".")

	command := cmd.NewRootCommand(cmd.CLIConfig{
		Version:           GatecheckVersion,
		PipedInput:        pipedFile,
		EPSSDownloadAgent: epss.NewAgent(http.DefaultClient, viper.GetString("GATECHECK_EPSS_URL")),
		KEVDownloadAgent:  kev.NewAgent(http.DefaultClient, viper.GetString("GATECHECK_KEV_URL")),

		DDExportService: &dojoService,
		DDExportTimeout: 5 * time.Minute,
		DDEngagement:    ddEngagement,

		AWSExportService: awsService,
		AWSExportTimeout: 5 * time.Minute,

		NewAsyncDecoderFunc: asyncDecoderFunc,

		ConfigMap:      viper.AllSettings(),
		ConfigFileUsed: viper.ConfigFileUsed(),
		ConfigPath:     "./gatecheck.env or $HOME/.config/gatecheck/gatecheck.env",
	})

	slog.SetDefault(slog.New(tint.NewHandler(command.ErrOrStderr(), &tint.Options{Level: slog.LevelWarn, TimeFormat: time.TimeOnly})))
	command.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	msg := `DEPRECATION NOTICE: A new version of the Gatecheck CLI will become the default in the next release. 
	See https://github.com/gatecheckdev/gatecheck for details`

	slog.Warn(msg)

	var startTime time.Time
	command.PersistentPreRun = func(cm *cobra.Command, _ []string) {
		startTime = time.Now()
		verbose, err := command.PersistentFlags().GetBool("verbose")
		if err != nil {
			panic(err)
		}
		if verbose {
			slog.SetDefault(slog.New(tint.NewHandler(command.ErrOrStderr(), &tint.Options{Level: slog.LevelDebug, TimeFormat: time.TimeOnly})))
		}
	}

	command.PersistentPostRun = func(_ *cobra.Command, _ []string) {
		elapsed := time.Since(startTime)
		slog.Debug("command execution complete", "elapsed", elapsed)
	}

	command.SilenceUsage = true

	err = command.Execute()

	if errors.Is(err, cmd.ErrorFileAccess) {
		slog.Error("file access error", "err", err)
		os.Exit(exitFileAccessFail)
	}

	if errors.Is(err, cmd.ErrorValidation) {
		os.Exit(exitValidationFail)
	}

	if err != nil {
		slog.Error("system failure", "err", err)
		os.Exit(exitSystemFail)
	}

	os.Exit(exitOk)
}

func asyncDecoderFunc() cmd.AsyncDecoder {
	decoder := new(gce.AsyncDecoder).WithDecoders(
		grype.NewReportDecoder(),
		semgrep.NewReportDecoder(),
		gitleaks.NewReportDecoder(),
		cyclonedx.NewReportDecoder(),
		archive.NewBundleDecoder(),
	)

	return decoder
}

// func ValidatorFuc(obj any, objConfig any) cmd.AnyValidator {
// 	switch obj.(type) {
// 	case
// 	}
// }

// PipeInput checks for input from a Linux Pipe ex. 'cat grype-report.json | gatecheck print'
func PipeInput() bool {
	fileInfo, _ := os.Stdin.Stat()
	return fileInfo.Mode()&os.ModeCharDevice == 0
}

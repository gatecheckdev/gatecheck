package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/kev"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"

	"github.com/spf13/cobra"
)

func newValidateCmd(newAsyncDecoder func() AsyncDecoder, KEVDownloadAgent io.Reader, EPSSDownloadAgent io.Reader) *cobra.Command {
	var validateAny func(obj any, configBytes []byte) error
	var validateBundle func(bundle *archive.Bundle, configBytes []byte) error

	var kevService *kev.Service
	var epssService *epss.Service
	cmd := &cobra.Command{
		Use:   "validate [FILE]",
		Short: "Validate reports or a bundle using thresholds set in the Gatecheck configuration file",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configFilename, _ := cmd.Flags().GetString("config")
			kevFilename, _ := cmd.Flags().GetString("kev-file")
			epssFilename, _ := cmd.Flags().GetString("epss-file")

			auditFlag, _ := cmd.Flags().GetBool("audit")
			kevFetchFlag, _ := cmd.Flags().GetBool("fetch-kev")
			epssFetchFlag, _ := cmd.Flags().GetBool("fetch-epss")

			// TODO: potential vul?
			slog.Debug("command", "cmd", "validate", "audit_flag", auditFlag, "target_filename", args[0],
				"config_filename", configFilename, "kev_filename", kevFilename,
				"epss_filename", epssFilename, "fetch_kev", kevFetchFlag, "fetch_epss", epssFetchFlag)

			decoder := newAsyncDecoder()

			obj, err := decoder.DecodeFrom(fileOrEmptyBuf(args[0]))
			if err != nil {
				slog.Error("failed async decoding", "filename", args[0], "err", err, "cmd", "validate")
				return fmt.Errorf("%w: async decoding: %v", ErrorEncoding, err)
			}

			configFileBytes, err := os.ReadFile(configFilename)
			if err != nil {
				return fmt.Errorf("%w: config file: %v", ErrorFileAccess, err)
			}

			if kevFetchFlag || kevFilename != "" {
				kevService, err = getKEVService(kevFilename, KEVDownloadAgent)
				if err != nil {
					return err
				}
			}

			if epssFetchFlag || epssFilename != "" {
				epssService, err = getEPSSService(epssFilename, EPSSDownloadAgent)
				if err != nil {
					return err
				}
			}

			err = validateAny(obj, configFileBytes)
			if err != nil && !errors.Is(err, gcv.ErrFailedRule) {
				return err
			}

			if err != nil && auditFlag {
				slog.Warn("[Audit]: %v\n", err)
				return nil
			}

			if err != nil {
				return fmt.Errorf("%w: %v", ErrorValidation, err)
			}
			slog.Info("successfully passed validation")
			return nil
		},
	}

	validateAny = func(v any, configBytes []byte) error {
		if bundle, ok := v.(*archive.Bundle); ok {
			return validateBundle(bundle, configBytes)
		}

		switch obj := v.(type) {
		case *semgrep.ScanReport:
			err := semgrep.NewValidator().ReadConfigAndValidate(obj.Results,
				bytes.NewReader(configBytes), semgrep.ConfigFieldName)
			slog.Info("semgrep report validation", "err", err)
			return err
		case *gitleaks.ScanReport:
			err := gitleaks.NewValidator().ReadConfigAndValidate(*obj,
				bytes.NewReader(configBytes), gitleaks.ConfigFieldName)
			slog.Info("gitleaks report validation", "err", err)
			return err
		case *cyclonedx.ScanReport:
			err := cyclonedx.NewValidator().ReadConfigAndValidate(*obj.Vulnerabilities,
				bytes.NewReader(configBytes), cyclonedx.ConfigFieldName)
			slog.Info("cyclonedx report validation", "err", err)
			return err
		}

		// This function is called after the async decoder so it has to be a defined type
		report := v.(*grype.ScanReport)
		var kevValidationErr error
		if kevService != nil {
			kevValidationErr = kevService.NewValidator().Validate(report.Matches, grype.Config{})
		}

		grypeValidator := grype.NewValidator()
		if epssService != nil {
			grypeValidator = grypeValidator.WithAllowRules(epssService.GrypeAllowRuleFunc())
			grypeValidator = grypeValidator.WithValidationRules(epssService.GrypeDenyRuleFunc())
		}

		grypeErr := grypeValidator.ReadConfigAndValidate(report.Matches, bytes.NewReader(configBytes), grype.ConfigFieldName)
		err := errors.Join(kevValidationErr, grypeErr)
		slog.Info("grype report validation", "err", err)
		return err
	}

	validateBundle = func(bundle *archive.Bundle, configBytes []byte) error {
		var bundleValidationError error
		for label := range bundle.Manifest().Files {
			slog.Info("Validate bundle file", "label", label)
			decoder := newAsyncDecoder()
			_, _ = bundle.WriteFileTo(decoder, label)
			obj, _ := decoder.Decode()
			if decoder.FileType() == gce.GenericFileType {
				continue
			}
			err := validateAny(obj, configBytes)
			bundleValidationError = errors.Join(bundleValidationError, err)
		}
		return bundleValidationError
	}

	cmd.Flags().Bool("audit", false, "Exit w/ Code 0 even if validation fails")
	cmd.Flags().StringP("config", "c", "", "A Gatecheck configuration file with thresholds")

	cmd.Flags().StringP("kev-file", "k", "", "A CISA KEV catalog file, JSON or CSV and cross reference Grype report")
	cmd.Flags().Bool("fetch-kev", false, "Download a CISA KEV catalog file and cross reference Grype report")

	cmd.Flags().StringP("epss-file", "e", "", "A downloaded CSV File with scores, note: will not query API")
	cmd.Flags().Bool("fetch-epss", false, "Download EPSS scores from API")

	_ = cmd.MarkFlagRequired("config")
	cmd.MarkFlagsMutuallyExclusive("kev-file", "fetch-kev")
	cmd.MarkFlagsMutuallyExclusive("epss-file", "fetch-epss")
	return cmd
}

func getKEVService(filename string, downloadAgent io.Reader) (*kev.Service, error) {
	if filename == "" {
		service := kev.NewService(downloadAgent)
		return service, service.Fetch()
	}

	service := kev.NewService(fileOrEmptyBuf(filename))

	return service, service.Fetch()
}

func getEPSSService(filename string, downloadAgent io.Reader) (*epss.Service, error) {
	if filename == "" {
		service := epss.NewService(downloadAgent)
		return service, service.Fetch()
	}

	service := epss.NewService(fileOrEmptyBuf(filename))
	return service, service.Fetch()
}

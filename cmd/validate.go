package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/blacklist"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func NewValidateCmd(decodeTimeout time.Duration) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "validate [FILE]",
		Short: "Validate reports or a bundle using thresholds set in the Gatecheck configuration file",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var config artifact.Config
			var kevBlacklist artifact.KEVCatalog
			var grypeScan artifact.GrypeScanReport

			var validationError error = nil

			configFilename, _ := cmd.Flags().GetString("config")
			kevFilename, _ := cmd.Flags().GetString("blacklist")
			audit, _ := cmd.Flags().GetBool("audit")

			// Open the config file
			configFile, err := os.Open(configFilename)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}
			if err := yaml.NewDecoder(configFile).Decode(&config); err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			// Open the target file
			targetBytes, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			err = ParseAndValidate(bytes.NewBuffer(targetBytes), config, decodeTimeout)
			cmd.PrintErrln(err)
			if err != nil {
				validationError = ErrorValidation
			}

			// Return early if no KEV file passed
			if kevFilename == "" {
				if audit {
					return nil
				}
				return validationError
			}

			kevFile, err := os.Open(kevFilename)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			if err := json.NewDecoder(kevFile).Decode(&kevBlacklist); err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			// Decode for Grype and return an error on fail because only grype can be validated with a blacklist
			if err := json.NewDecoder(bytes.NewBuffer(targetBytes)).Decode(&grypeScan); err != nil {
				return fmt.Errorf("%w: only Grype Reports are supported with KEV: %v", ErrorEncoding, err)
			}

			vulnerabilities := blacklist.BlacklistedVulnerabilities(grypeScan, kevBlacklist)

			cmd.Println(blacklist.StringBlacklistedVulnerabilities(kevBlacklist.CatalogVersion, vulnerabilities))

			cmd.Println(fmt.Sprintf("%d Vulnerabilities listed on CISA Known Exploited Vulnerabilities Blacklist",
				len(vulnerabilities)))

			if len(vulnerabilities) > 0 {
				validationError = ErrorValidation
			}

			if audit == true {
				return nil
			}

			return validationError
		},
	}

	cmd.Flags().Bool("audit", false, "Exit w/ Code 0 even if validation fails")
	cmd.Flags().StringP("config", "c", "", "A Gatecheck configuration file with thresholds")
	cmd.Flags().StringP("blacklist", "k", "", "A CISA KEV Blacklist file")

	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func NewEPSSCmd(service EPSSService) *cobra.Command {

	var EPSSCmd = &cobra.Command{
		Use:   "epss <Grype FILE>",
		Short: "Query first.org for Exploit Prediction Scoring System (EPSS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var grypeScan artifact.GrypeScanReport
			var csvFile *os.File
			var err error

			csvFilename, _ := cmd.Flags().GetString("file")

			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}
			if csvFilename != "" {
				csvFile, err = os.Open(csvFilename)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}
			}

			if err := json.NewDecoder(f).Decode(&grypeScan); err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			CVEs := make([]epss.CVE, len(grypeScan.Matches))

			for i, match := range grypeScan.Matches {
				CVEs[i] = epss.CVE{
					ID:       match.Vulnerability.ID,
					Severity: match.Vulnerability.Severity,
					Link:     match.Vulnerability.DataSource,
				}
			}

			var output string
			if csvFile != nil {
				output, err = epssFromDataStore(csvFile, CVEs)
			} else {
				output, err = epssFromAPI(service, CVEs)
			}

			if err == nil {
				cmd.Println(output)
			}

			return err
		},
	}

	EPSSCmd.Flags().StringP("file", "f", "", "A downloaded CSV File with scores, note: will not query API")

	return EPSSCmd
}

func epssFromAPI(service EPSSService, CVEs []epss.CVE) (string, error) {

	data, err := service.Get(CVEs)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrorAPI, err)
	}

	return epss.Sprint(data), nil
}

func epssFromDataStore(epssCSV io.Reader, CVEs []epss.CVE) (string, error) {
	store := epss.NewDataStore()
	data := make([]epss.Data, len(CVEs))

	for i := range data {
		vul, err := store.Get(CVEs[i].ID)
		if err != nil {
			return "", err
		}
		data[i].CVE = CVEs[i].ID
		data[i].Severity = CVEs[i].Severity
		data[i].URL = CVEs[i].Link
		data[i].EPSS = fmt.Sprintf("%.2f%%", 100*vul.Probability)
		data[i].Percentile = fmt.Sprintf("%.2f%%", 100*vul.Percentile)

	}
	return epss.Sprint(data), nil
}

func ParseAndValidate(r io.Reader, config artifact.Config, timeout time.Duration) error {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rType, b, err := artifact.ReadWithContext(ctx, r)

	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(b)

	// No need to check decode errors since it's decoded in the DetectReportType Function
	switch rType {
	case artifact.Semgrep:
		if config.Semgrep == nil {
			return errors.New("no Semgrep configuration specified")
		}
		err = artifact.ValidateSemgrep(*config.Semgrep, artifact.DecodeJSON[artifact.SemgrepScanReport](buf))
	case artifact.Cyclonedx:
		if config.Cyclonedx == nil {
			return errors.New("no CycloneDx configuration specified")
		}
		err = artifact.ValidateCyclonedx(*config.Cyclonedx, artifact.DecodeJSON[artifact.CyclonedxSbomReport](buf))
	case artifact.Grype:
		if config.Grype == nil {
			return errors.New("no Grype configuration specified")
		}
		err = artifact.ValidateGrype(*config.Grype, artifact.DecodeJSON[artifact.GrypeScanReport](buf))
	case artifact.Gitleaks:
		if config.Gitleaks == nil {
			return errors.New("no Gitleaks configuration specified")
		}
		err = artifact.ValidateGitleaks(*config.Gitleaks, artifact.DecodeJSON[artifact.GitleaksScanReport](buf))
	case artifact.GatecheckBundle:
		var errStrings []string
		bundle := artifact.DecodeBundle(buf)
		if err := bundle.ValidateCyclonedx(config.Cyclonedx); err != nil {
			errStrings = append(errStrings, err.Error())
		}
		if err := bundle.ValidateGrype(config.Grype); err != nil {
			errStrings = append(errStrings, err.Error())
		}
		if err := bundle.ValidateSemgrep(config.Semgrep); err != nil {
			errStrings = append(errStrings, err.Error())
		}
		if err := bundle.ValidateGitleaks(config.Gitleaks); err != nil {
			errStrings = append(errStrings, err.Error())
		}
		if len(errStrings) == 0 {
			return nil
		}
		return errors.New(strings.Join(errStrings, "\n"))

	default:
		err = errors.New("unsupported scan type")
	}

	return err

}

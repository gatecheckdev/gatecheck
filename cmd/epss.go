package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/spf13/cobra"
)

func NewEPSSCmd(service EPSSService) *cobra.Command {

	var downloadCmd = &cobra.Command{
		Use:   "download",
		Short: "EPSS CSV with scores for all CVEs (outputs to STDOUT)",
		RunE: func(cmd *cobra.Command, args []string) error {
			url, _ := cmd.Flags().GetString("url")

			n , err := service.WriteCSV(cmd.OutOrStdout(), url)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorAPI, err)
			}
			
			log.Infof("%d bytes written to STDOUT", n)
			return nil
		},
	}

	today := time.Now()
	defaultURL := fmt.Sprintf("https://epss.cyentia.com/epss_scores-%d-%s-%s.csv.gz", today.Year(), today.Format("01"), today.Format("02"))
	downloadCmd.Flags().StringP("url", "u", defaultURL, "The URL for the CSV file")

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

	EPSSCmd.AddCommand(downloadCmd)

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
	if err := epss.NewCSVDecoder(epssCSV).Decode(store); err != nil {
		return "", err
	}
	log.Infof("EPSS CSV Datastore imported scores for %d CVEs\n", store.Len())

	for i := range data {
		data[i].CVE = CVEs[i].ID
		data[i].Severity = CVEs[i].Severity
		data[i].URL = CVEs[i].Link
		data[i].Date = store.ScoreDate().Format("2006-01-02")
		err := store.Write(&data[i])
		if err != nil {
			return "", err
		}
	}
	return epss.Sprint(data), nil
}

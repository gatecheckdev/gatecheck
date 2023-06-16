package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	"github.com/spf13/cobra"
)

func NewEPSSCmd(EPSSDownloadAgent io.Reader) *cobra.Command {

	var downloadCmd = &cobra.Command{
		Use:   "download",
		Short: "EPSS CSV with scores for all CVEs (outputs to STDOUT)",
		RunE: func(cmd *cobra.Command, args []string) error {

			n, err := io.Copy(cmd.OutOrStdout(), EPSSDownloadAgent)
			if err != nil {
				return err
			}

			log.Infof("%d bytes written to STDOUT", n)
			return nil
		},
	}

	var EPSSCmd = &cobra.Command{
		Use:   "epss <Grype FILE>",
		Short: "Query first.org for Exploit Prediction Scoring System (EPSS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var csvFile *os.File
			var err error
			var service *epss.Service

			csvFilename, _ := cmd.Flags().GetString("epss-file")
			fetchFlag, _ := cmd.Flags().GetBool("fetch")

			grypeFile, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			if fetchFlag {
				service = epss.NewService(EPSSDownloadAgent)
			}

			if csvFilename != "" {
				csvFile, err = os.Open(csvFilename)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}
				service = epss.NewService(csvFile)
			}

			if service == nil {
				return fmt.Errorf("%w: No EPSS file or --fetch flag", ErrorUserInput)
			}

			r, err := grype.NewReportDecoder().DecodeFrom(grypeFile)

			if err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			grypeScan := r.(*grype.ScanReport)

			if err := service.Fetch(); err != nil {
				return err
			}
			cves, err := service.GetCVEs(grypeScan.Matches)
			if err != nil {
				return err
			}

			_, err = format.NewTableWriter(epssTable(cves)).WriteTo(cmd.OutOrStderr())
			return err
		},
	}

	EPSSCmd.AddCommand(downloadCmd)

	EPSSCmd.Flags().StringP("epss-file", "e", "", "A downloaded CSV File with scores, note: will not query API")
	EPSSCmd.Flags().Bool("fetch", false, "Fetch EPSS scores from API")

	return EPSSCmd
}

func epssTable(input []epss.CVE) *format.Table {

	table := format.NewTable()

	table.AppendRow("CVE", "Severity", "EPSS Score", "Percentile", "Link")

	for _, cve := range input {
		table.AppendRow(cve.ID, cve.Severity, fmt.Sprintf("%.5f", cve.Probability),
			fmt.Sprintf("%.2f%%", 100*cve.Percentile), cve.Link)
	}

	table.SetSort(2, func(a, b string) bool {
		return a > b
	})
	sort.Sort(table)

	return table
}

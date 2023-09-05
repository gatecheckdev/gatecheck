package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"sort"

	gio "github.com/gatecheckdev/gatecheck/internal/io"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	"github.com/spf13/cobra"
)

func newEPSSCmd(EPSSDownloadAgent io.Reader) *cobra.Command {

	var downloadCmd = &cobra.Command{
		Use:   "download",
		Short: "EPSS CSV with scores for all CVEs (outputs to STDOUT)",
		RunE: func(cmd *cobra.Command, args []string) error {

			n, err := io.Copy(cmd.OutOrStdout(), EPSSDownloadAgent)
			if err != nil {
				return err
			}

			slog.Info("write to STDOUT", "bytes_written", n)
			return nil
		},
	}

	var EPSSCmd = &cobra.Command{
		Use:   "epss <Grype FILE>",
		Short: "Query first.org for Exploit Prediction Scoring System (EPSS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			var service *epss.Service

			csvFilename, _ := cmd.Flags().GetString("epss-file")
			fetchFlag, _ := cmd.Flags().GetBool("fetch")

			if fetchFlag {
				service = epss.NewService(EPSSDownloadAgent)
			}

			if csvFilename != "" {
				service = epss.NewService(gio.NewLazyReader(csvFilename))
			}

			if service == nil {
				return fmt.Errorf("%w: No EPSS file or --fetch flag", ErrorUserInput)
			}

			r, err := grype.NewReportDecoder().DecodeFrom(gio.NewLazyReader(args[0]))

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
	EPSSCmd.MarkFlagsMutuallyExclusive("epss-file", "fetch")

	return EPSSCmd
}

func epssTable(input []epss.CVE) *format.Table {

	table := format.NewTable()

	table.AppendRow("CVE", "Severity", "EPSS Score", "Percentile", "Link")

	for _, cve := range input {
		prob := "-"
		perc := "-"
		if cve.Probability != 0 {
			prob = fmt.Sprintf("%.5f", cve.Probability)
		}
		if cve.Percentile != 0 {
			perc = fmt.Sprintf("%.2f%%", 100*cve.Percentile)
		}
		table.AppendRow(cve.ID, cve.Severity, prob, perc, cve.Link)
	}

	table.SetSort(2, func(a, b string) bool {
		return a > b
	})
	sort.Sort(table)

	return table
}

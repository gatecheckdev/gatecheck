package cmd

import (
	"github.com/gatecheckdev/gatecheck/pkg/entity"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/spf13/cobra"
)

func NewEPSSCmd(service epss.Service) *cobra.Command {

	var EPSSCmd = &cobra.Command{
		Use:   "epss <Grype FILE>",
		Short: "Query first.org for Exploit Prediction Scoring System (EPSS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			grypeReport, err := OpenAndDecode[entity.GrypeScanReport](args[0], JSON)
			if err != nil {
				return err
			}

			CVEs := make([]epss.CVE, len(grypeReport.Matches))
			for i, match := range grypeReport.Matches {
				CVEs[i] = epss.CVE{
					ID:       match.Vulnerability.ID,
					Severity: match.Vulnerability.Severity,
					Link:     match.Vulnerability.DataSource,
				}
			}

			data, err := service.Get(CVEs)
			if err != nil {
				return err
			}
			cmd.Println(epss.Sprint(data))
			return nil
		},
	}

	return EPSSCmd
}

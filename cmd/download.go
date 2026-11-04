package cmd

import (
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

func newDownloadCommand() *cobra.Command {
	downloadCmd := &cobra.Command{
		Use:   "download",
		Short: "output data from supported APIs",
	}

	epssCmd := &cobra.Command{
		Use:   "epss",
		Short: "download epss data from FIRST API as csv to STDOUT",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := append([]gatecheck.Option{gatecheck.WithEPSSURL(stringSetting(cmd, "epss-url", "GATECHECK_EPSS_URL"))}, epssCacheOptions(cmd)...)
			return gatecheck.DownloadEPSS(cmd.OutOrStdout(), opts...)
		},
	}
	addEPSSFlags(epssCmd, false)

	kevCmd := &cobra.Command{
		Use:   "kev",
		Short: "download kev catalog from CISA as json to STDOUT",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return gatecheck.DownloadKEV(cmd.OutOrStdout(), gatecheck.WithKEVURL(stringSetting(cmd, "kev-url", "GATECHECK_KEV_URL")))
		},
	}
	kevCmd.Flags().String("kev-url", "", `CISA KEV JSON URL; "" uses the official feed (env GATECHECK_KEV_URL)`)

	downloadCmd.AddCommand(epssCmd, kevCmd)
	return downloadCmd
}

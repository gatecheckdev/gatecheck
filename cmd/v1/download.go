package cmd

import (
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newDownloadCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "download",
		RunE: runList,
		Args: cobra.MaximumNArgs(1),
	}

	epssCmd := newBasicCommand("epss", "download epss data from FIRST API as csv to STDOUT", runDownloadEPSS)
	kevCmd := newBasicCommand("kev", "download kev catalog from CISA as json to STDOUT", runDownloadKEV)

	cmd.AddCommand(epssCmd, kevCmd)
	return cmd
}

func runDownloadEPSS(cmd *cobra.Command, _ []string) error {
	epssURL := viper.GetString("api.epss-url")

	return gatecheck.DownloadEPSS(cmd.OutOrStdout(), gatecheck.WithEPSSURL(epssURL))
}

func runDownloadKEV(cmd *cobra.Command, _ []string) error {
	kevURL := viper.GetString("api.kev-url")
	return gatecheck.DownloadKEV(cmd.OutOrStdout(), gatecheck.WithKEVURL(kevURL))
}

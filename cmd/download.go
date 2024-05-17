package cmd

import (
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "output data from supported APIs",
}

var downloadEPSSCmd = &cobra.Command{
	Use:   "epss",
	Short: "download epss data from FIRST API as csv to STDOUT",
	RunE: func(cmd *cobra.Command, args []string) error {
		url := RuntimeConfig.EPSSURL.Value().(string)
		return gatecheck.DownloadEPSS(cmd.OutOrStdout(), gatecheck.WithEPSSURL(url))
	},
}

var downloadKEVCmd = &cobra.Command{
	Use:   "kev",
	Short: "download kev catalog from CISA as json to STDOUT",
	RunE: func(cmd *cobra.Command, args []string) error {
		url := RuntimeConfig.KEVURL.Value().(string)
		return gatecheck.DownloadKEV(cmd.OutOrStdout(), gatecheck.WithKEVURL(url))
	},
}

func newDownloadCommand() *cobra.Command {
	RuntimeConfig.EPSSURL.SetupCobra(downloadEPSSCmd)
	RuntimeConfig.KEVURL.SetupCobra(downloadKEVCmd)
	downloadCmd.AddCommand(downloadEPSSCmd, downloadKEVCmd)
	return downloadCmd
}

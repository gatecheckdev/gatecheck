package cmd

import (
	"os"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

const inputTypes = "grype|cyclonedx|semgrep|gitleaks|trivy|osv|syft|sarif|bundle|lcov|clover|cobertura"

// addEPSSFlags adds the EPSS source and cache flags. withFile adds --epss-filename.
func addEPSSFlags(cmd *cobra.Command, withFile bool) {
	flags := cmd.Flags()
	flags.String("epss-url", "", `FIRST.org EPSS CSV URL; "" uses the official feed (env GATECHECK_EPSS_URL)`)
	flags.String("epss-cache-dir", "", "cache directory for EPSS downloads (default: user cache dir, env GATECHECK_EPSS_CACHE_DIR)")
	flags.Bool("epss-no-cache", false, "download EPSS on every run instead of using the local cache (env GATECHECK_EPSS_CACHE=off)")
	if withFile {
		flags.String("epss-filename", "", "local FIRST.org EPSS CSV to use instead of downloading (env GATECHECK_EPSS_FILENAME)")
	}
}

func addKEVFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.String("kev-url", "", `CISA KEV JSON URL; "" uses the official feed (env GATECHECK_KEV_URL)`)
	flags.String("kev-filename", "", "local CISA KEV JSON to use instead of downloading (env GATECHECK_KEV_FILENAME)")
}

// epssCacheOptions reads --epss-no-cache and --epss-cache-dir. GATECHECK_EPSS_CACHE
// and GATECHECK_EPSS_CACHE_DIR are read by the epss package when these are unset.
func epssCacheOptions(cmd *cobra.Command) []gatecheck.Option {
	var opts []gatecheck.Option
	if noCache, _ := cmd.Flags().GetBool("epss-no-cache"); noCache {
		opts = append(opts, gatecheck.WithEPSSCache(false))
	}
	if dir, _ := cmd.Flags().GetString("epss-cache-dir"); strings.TrimSpace(dir) != "" {
		opts = append(opts, gatecheck.WithEPSSCacheDir(dir))
	}
	return opts
}

// fetchOptions builds the EPSS and KEV options for validate. The returned
// function closes any files it opened.
func fetchOptions(cmd *cobra.Command) ([]gatecheck.Option, func(), error) {
	var files []*os.File
	closeAll := func() {
		for _, f := range files {
			_ = f.Close()
		}
	}
	opts := []gatecheck.Option{
		gatecheck.WithEPSSURL(stringSetting(cmd, "epss-url", "GATECHECK_EPSS_URL")),
		gatecheck.WithKEVURL(stringSetting(cmd, "kev-url", "GATECHECK_KEV_URL")),
	}
	opts = append(opts, epssCacheOptions(cmd)...)

	if name := stringSetting(cmd, "epss-filename", "GATECHECK_EPSS_FILENAME"); name != "" {
		f, err := os.Open(name)
		if err != nil {
			return nil, closeAll, err
		}
		files = append(files, f)
		opts = append(opts, gatecheck.WithEPSSFile(f))
	}
	if cmd.Flags().Lookup("kev-filename") != nil {
		if name := stringSetting(cmd, "kev-filename", "GATECHECK_KEV_FILENAME"); name != "" {
			f, err := os.Open(name)
			if err != nil {
				closeAll()
				return nil, func() {}, err
			}
			files = append(files, f)
			opts = append(opts, gatecheck.WithKEVFile(f))
		}
	}
	return opts, closeAll, nil
}

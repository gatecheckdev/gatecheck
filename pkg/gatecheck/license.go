package gatecheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
	"github.com/gatecheckdev/gatecheck/pkg/license"
	"github.com/gatecheckdev/gatecheck/pkg/vex"
	"github.com/olekukonko/tablewriter"
)

// configLicense gates SBOM package licenses. It applies to Syft JSON and to
// CycloneDX components.
type configLicense struct {
	Enabled bool `json:"enabled" toml:"enabled" yaml:"enabled"`
	// Deny are case-insensitive glob patterns, such as "GPL-*".
	Deny []string `json:"deny" toml:"deny" yaml:"deny"`
	// Allow, when not empty, fails every license that matches none of these patterns.
	Allow []string `json:"allow" toml:"allow" yaml:"allow"`
	// DenyUnknown fails packages that declare no license.
	DenyUnknown bool `json:"denyUnknown" toml:"denyUnknown" yaml:"denyUnknown"`
	// PackageRiskAcceptance skips license checks for these packages.
	PackageRiskAcceptance []configLicensePackage `json:"packageRiskAcceptance" toml:"packageRiskAcceptance" yaml:"packageRiskAcceptance"`
}

type configLicensePackage struct {
	// Name matches the package name without regard to case.
	Name string `json:"name" toml:"name" yaml:"name"`
	// PURL matches by type, namespace, and name, and by version when it has one.
	PURL     string `json:"purl" toml:"purl" yaml:"purl"`
	Metadata struct {
		Tags []string `json:"tags" toml:"tags" yaml:"tags"`
	} `json:"metadata" toml:"metadata" yaml:"metadata"`
}

func (c configLicensePackage) matches(pkg license.Package) bool {
	if c.PURL != "" {
		return pkg.PURL != "" && vex.PURLMatches(c.PURL, pkg.PURL)
	}
	return c.Name != "" && strings.EqualFold(c.Name, pkg.Name)
}

func defaultConfigLicense() configLicense {
	return configLicense{
		Deny:                  []string{},
		Allow:                 []string{},
		PackageRiskAcceptance: []configLicensePackage{},
	}
}

// ruleLicense returns a validation error when a package license fails the policy.
func ruleLicense(config *Config, artifact string, pkgs []license.Package) error {
	cfg := config.License
	if !cfg.Enabled {
		slog.Debug("license limit not enabled", "artifact", artifact, "packages", len(pkgs))
		return nil
	}
	policy := license.Policy{Deny: cfg.Deny, Allow: cfg.Allow, DenyUnknown: cfg.DenyUnknown}
	var violations []license.Violation
	for _, pkg := range pkgs {
		v, failed := policy.Check(pkg)
		if !failed {
			continue
		}
		if slices.ContainsFunc(cfg.PackageRiskAcceptance, func(c configLicensePackage) bool { return c.matches(pkg) }) {
			slog.Info("license risk accepted for package", "artifact", artifact, "package", pkg.Name, "version", pkg.Version, "license", v.License)
			continue
		}
		violations = append(violations, v)
	}
	if len(violations) == 0 {
		slog.Info("license limit valid", "artifact", artifact, "packages", len(pkgs))
		return nil
	}
	for _, v := range violations {
		slog.Error("license violation", "artifact", artifact, "package", v.Package.Name, "version", v.Package.Version, "purl", v.Package.PURL, "reason", v.Reason)
	}
	return newValidationErr(fmt.Sprintf("License: %d package(s) failed the license policy", len(violations)))
}

func syftPackages(report *artifacts.SyftReportMin) []license.Package {
	pkgs := make([]license.Package, 0, len(report.Artifacts))
	for _, a := range report.Artifacts {
		pkgs = append(pkgs, license.Package{Name: a.Name, Version: a.Version, PURL: a.PURL, Licenses: a.LicenseNames()})
	}
	return pkgs
}

// cyclonedxPackages flattens components, including nested ones.
func cyclonedxPackages(components []artifacts.CyclonedxComponent) []license.Package {
	var pkgs []license.Package
	for _, c := range components {
		pkgs = append(pkgs, license.Package{Name: c.Name, Version: c.Version, PURL: c.PURL, Licenses: c.LicenseNames()})
		pkgs = append(pkgs, cyclonedxPackages(c.Components)...)
	}
	return pkgs
}

func validateSyftReport(r io.Reader, config *Config) error {
	slog.Debug("validate syft report")
	report := &artifacts.SyftReportMin{}
	if err := json.NewDecoder(r).Decode(report); err != nil {
		slog.Error("decode syft report for validation", "error", err)
		return errors.New("cannot run Syft validation: Report decoding failed, See log for details")
	}
	return ruleLicense(config, "syft", syftPackages(report))
}

func listSyft(table *tablewriter.Table, src io.Reader) error {
	report := &artifacts.SyftReportMin{}
	if err := json.NewDecoder(src).Decode(report); err != nil {
		return err
	}
	if len(report.Artifacts) == 0 {
		return emptyReport("No syft packages")
	}
	rows := make([][]string, 0, len(report.Artifacts))
	for _, a := range report.Artifacts {
		licenses := strings.Join(a.LicenseNames(), ", ")
		if licenses == "" {
			licenses = "-"
		}
		rows = append(rows, []string{a.Name, a.Version, a.Type, licenses})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i][0] == rows[j][0] {
			return rows[i][1] < rows[j][1]
		}
		return rows[i][0] < rows[j][0]
	})
	table.Header([]string{"Syft Package", "Version", "Type", "Licenses"})
	for _, row := range rows {
		if err := table.Append(row); err != nil {
			return err
		}
	}
	return nil
}

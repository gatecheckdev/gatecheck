package gatecheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/v1"
	"github.com/gatecheckdev/gatecheck/pkg/epss/v1"
	"github.com/gatecheckdev/gatecheck/pkg/format"
)

func List(dst io.Writer, src io.Reader, inputFilename string) error {

	switch {
	case strings.Contains(inputFilename, "grype"):
		slog.Debug("list", "filename", inputFilename, "filetype", "grype")
		return ListGrypeReport(dst, src)

	case strings.Contains(inputFilename, "cyclonedx"):
		slog.Debug("list", "filename", inputFilename, "filetype", "cyclonedx")
		return ListCyclonedx(dst, src)

	case strings.Contains(inputFilename, "semgrep"):
		slog.Debug("list", "filename", inputFilename, "filetype", "semgrep")
		return errors.New("semgrep not implemented yet")

	case strings.Contains(inputFilename, "gitleaks"):
		slog.Debug("list", "filename", inputFilename, "filetype", "gitleaks")
		return errors.New("gitleaks not implemented yet")

	case strings.Contains(inputFilename, "syft"):
		slog.Debug("list", "filename", inputFilename, "filetype", "syft")
		slog.Warn("syft decoder is not supported yet")
		return errors.New("syft not implemented yet")

	case strings.Contains(inputFilename, "bundle"):
		slog.Debug("list", "filename", inputFilename, "filetype", "bundle")
		bundle, err := archive.UntarGzipBundle(src)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(dst, bundle.Content())
		return err

	default:
		slog.Error("invalid input filetype", "filename", inputFilename)
		return errors.New("failed to list artifact content")
	}
}

// ListAll will print a table of vulnerabilities with EPSS Score and Percentile
//
// if epssURL is "", it will use the default value
func ListAll(dst io.Writer, src io.Reader, inputFilename string, client *http.Client, epssURL string) error {

	epssData := new(epss.Data)
	fetchOptions := epss.DefaultFetchOptions()
	fetchOptions.Client = client
	if epssURL != "" {
		fetchOptions.URL = epssURL
	}
	if err := epss.FetchData(epssData); err != nil {
		return err
	}

	switch {
	case strings.Contains(inputFilename, "grype"):
		slog.Debug("list all, decode", "filename", inputFilename, "filetype", "grype")
		return listGrypeWithEPSS(dst, src, epssData)

	case strings.Contains(inputFilename, "cyclonedx"):
		slog.Debug("list", "filename", inputFilename, "filetype", "cyclonedx")
		return errors.New("cyclonedx not implemented yet")

	default:
		slog.Error("unsupport file type", "filename", inputFilename)
		return errors.New("failed to list artifact content")
	}
}

func ListGrypeReport(dst io.Writer, src io.Reader) error {
	report := &artifacts.GrypeReportMin{}
	slog.Debug("decode grype report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return err
	}
	table := format.NewTable()
	table.AppendRow("Severity", "Package", "Version", "Link")

	for _, item := range report.Matches {
		table.AppendRow(item.Vulnerability.Severity, item.Artifact.Name, item.Artifact.Version, item.Vulnerability.DataSource)
	}

	table.SetSort(0, format.NewCatagoricLess([]string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}))

	sort.Sort(table)

	_, err := format.NewTableWriter(table).WriteTo(dst)
	return err
}

func listGrypeWithEPSS(dst io.Writer, src io.Reader, epssData *epss.Data) error {
	report := &artifacts.GrypeReportMin{}
	slog.Debug("decode grype report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return err
	}

	table := format.NewTable()
	table.AppendRow("CVE ID", "Severity", "EPSS Score", "EPSS Prctl", "Package", "Version", "Link")

	for _, item := range report.Matches {
		cve, ok := epssData.CVEs[item.Vulnerability.ID]
		score := "-"
		prctl := "-"
		if ok {
			score = cve.EPSS
			prctl = cve.Percentile
		}
		table.AppendRow(
			item.Vulnerability.ID,
			item.Vulnerability.Severity,
			score,
			prctl,
			item.Artifact.Name,
			item.Artifact.Version,
			item.Vulnerability.DataSource,
		)
	}

	table.SetSort(1, format.NewCatagoricLess([]string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}))

	sort.Sort(table)

	_, err := format.NewTableWriter(table).WriteTo(dst)

	return err
}

func ListCyclonedx(dst io.Writer, src io.Reader) error {

	report := &artifacts.CyclonedxReportMin{}
	slog.Debug("decode cyclonedx report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return err
	}
	table := format.NewTable()
	table.AppendRow("CVE ID", "Severity", "Package", "Link")
	severity := "-"
	pkgs := "-"
	link := "-"
	for idx, vul := range report.Vulnerabilities {
		severity = report.HighestSeverity(idx)
		pkgs = report.AffectedPackages(idx)
		if len(vul.Advisories) > 0 {
			link = vul.Advisories[0].URL
		}
		// get the affected vulnerability
		table.AppendRow(vul.ID, severity, pkgs, link)
	}

	table.SetSort(1, format.NewCatagoricLess([]string{"critical", "high", "medium", "low", "none"}))
	sort.Sort(table)

	_, err := format.NewTableWriter(table).WriteTo(dst)
	return err
}

func listCyclonedxWithEPSSOld(dst io.Writer, report *cyclonedx.ScanReport, epssData *epss.Data) error {

	if report.Components == nil {
		return errors.New("No Components in Report")
	}

	components := make(map[string]cdx.Component, len(*report.Components))
	for _, item := range *report.Components {
		components[item.BOMRef] = item
	}

	table := format.NewTable()
	table.AppendRow("CVE ID", "Severity", "EPSS Score", "EPSS Prctl", "Package", "Version", "Link")
	severities := make(map[string]int)

	for _, vul := range *report.Vulnerabilities {
		severity := string(cyclonedx.HighestVulnerability(*vul.Ratings).Severity)
		severity = strings.ToUpper(severity[:1]) + severity[1:]
		severities[severity] = severities[severity] + 1

		pkg := "Not Specified"
		version := "Not Specified"
		link := "Not Specified"

		if vul.Source != nil {
			link = vul.Source.URL
		}

		if vul.Affects != nil {
			for _, affected := range *vul.Affects {
				component, ok := components[affected.Ref]
				if !ok {
					pkg = format.Summarize(affected.Ref, 50, format.ClipRight)
					continue
				}
				pkg = component.Name
				version = component.Version
			}
		}
		cve, ok := epssData.CVEs[vul.ID]
		score := "-"
		prctl := "-"
		if ok {
			score = cve.EPSS
			prctl = cve.Percentile
		}
		table.AppendRow(vul.ID, score, prctl, severity, pkg, version, link)
	}
	table.SetSort(1, format.NewCatagoricLess(cyclonedx.OrderedSeverities))
	sort.Sort(table)

	_, err := format.NewTableWriter(table).WriteTo(dst)

	return err
}

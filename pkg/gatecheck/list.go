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

	"github.com/gatecheckdev/gatecheck/pkg/archive"
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
		return ListSemgrep(dst, src)

	case strings.Contains(inputFilename, "gitleaks"):
		slog.Debug("list", "filename", inputFilename, "filetype", "gitleaks")
		return listGitleaks(dst, src)

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
func ListAll(dst io.Writer, src io.Reader, inputFilename string, client *http.Client, epssURL string, epssFile io.Reader) error {
	epssData := new(epss.Data)

	// Load EPSS data from a file or fetch the data from API
	switch {
	case epssFile != nil:
		if err := epss.ParseEPSSDataCSV(epssFile, epssData); err != nil {
			return errors.New("Failed to decode EPSS data file. See log for details.")
		}
	default:
		fetchOptions := epss.DefaultFetchOptions()
		fetchOptions.Client = client
		if epssURL != "" {
			fetchOptions.URL = epssURL
		}
		if err := epss.FetchData(epssData); err != nil {
			return err
		}
	}

	switch {
	case strings.Contains(inputFilename, "grype"):
		slog.Debug("list all grype vulnerabilities", "filename", inputFilename)
		return listGrypeWithEPSS(dst, src, epssData)

	case strings.Contains(inputFilename, "cyclonedx"):
		slog.Debug("list all cyclonedx vulnerabilities", "filename", inputFilename)
		return listCyclonedxWithEPSS(dst, src, epssData)

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
	link := "-"
	for idx, vul := range report.Vulnerabilities {
		severity := vul.HighestSeverity()
		pkgs := report.AffectedPackages(idx)
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

func listCyclonedxWithEPSS(dst io.Writer, src io.Reader, epssData *epss.Data) error {
	report := &artifacts.CyclonedxReportMin{}
	slog.Debug("decode grype report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return err
	}

	table := format.NewTable()
	table.AppendRow("CVE ID", "Severity", "EPSS Score", "EPSS Prctl", "affected Packages", "Link")

	for idx, item := range report.Vulnerabilities {
		cve, ok := epssData.CVEs[item.ID]
		score := "-"
		prctl := "-"
		if ok {
			score = cve.EPSS
			prctl = cve.Percentile
		}
		link := "-"
		if len(item.Advisories) > 0 {
			link = item.Advisories[0].URL
		}
		table.AppendRow(
			item.ID,
			item.HighestSeverity(),
			score,
			prctl,
			report.AffectedPackages(idx),
			link,
		)
	}

	table.SetSort(1, format.NewCatagoricLess([]string{"critical", "high", "medium", "low", "info", "none", "unknown"}))

	sort.Sort(table)

	_, err := format.NewTableWriter(table).WriteTo(dst)

	return err
}

func ListSemgrep(dst io.Writer, src io.Reader) error {
	report := &artifacts.SemgrepReportMin{}

	if err := json.NewDecoder(src).Decode(report); err != nil {
		return err
	}

	for _, semgrepError := range report.Errors {
		slog.Warn("semgrep runtime error",
			"level", semgrepError.Level,
			"message", semgrepError.ShortMessage(),
			"path", semgrepError.Path,
		)
	}

	table := format.NewTable()
	table.AppendRow("ID", "Owasp IDs", "Severity", "Impact", "link")

	for _, result := range report.Results {
		table.AppendRow(
			result.ShortCheckID(),
			result.Extra.Metadata.OwaspIDs(),
			result.Extra.Severity,
			result.Extra.Metadata.Impact,
			result.Extra.Metadata.Shortlink,
		)
	}

	table.SetSort(1, format.NewCatagoricLess([]string{"ERROR", "WARNING", "INFO"}))
	sort.Sort(table)
	_, err := format.NewTableWriter(table).WriteTo(dst)

	return err
}

func listGitleaks(dst io.Writer, src io.Reader) error {
	report := &artifacts.GitLeaksReportMin{}
	if err := json.NewDecoder(src).Decode(report); err != nil {
		return err
	}

	table := format.NewTable()

	table.AppendRow("Rule ID", "File", "Commit", "Start Line")

	for _, finding := range *report {
		table.AppendRow(
			finding.RuleID,
			finding.FileShort(),
			finding.CommitShort(),
			fmt.Sprintf("%d", finding.StartLine),
		)
	}

	_, err := format.NewTableWriter(table).WriteTo(dst)

	if report.Count() == 0 {
		fmt.Fprintln(dst, "        No Gitleaks Findings")
	}

	return err
}

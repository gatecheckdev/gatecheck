package gatecheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/v1"
	"github.com/gatecheckdev/gatecheck/pkg/epss/v1"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	"github.com/olekukonko/tablewriter"
)

type listOptions struct {
	displayFormat string
	epssData      *epss.Data
}

type ListOptionFunc func(*listOptions)

func WithDisplayFormat(displayFormat string) func(*listOptions) {
	return func(o *listOptions) {
		o.displayFormat = displayFormat
	}
}

func WithEPSS(epssFile *os.File, epssURL string) (func(*listOptions), error) {
	data := &epss.Data{}
	f := func(o *listOptions) {
		o.epssData = data
	}

	if epssFile == nil {
		err := epss.FetchData(data, epss.WithURL(epssURL))
		return f, err
	}

	err := epss.ParseEPSSDataCSV(epssFile, data)

	return f, err
}

func List(dst io.Writer, src io.Reader, inputFilename string, options ...ListOptionFunc) error {
	var table *tablewriter.Table
	var err error
	o := &listOptions{}
	for _, f := range options {
		f(o)
	}

	switch {
	case strings.Contains(inputFilename, "grype"):
		slog.Debug("list", "filename", inputFilename, "filetype", "grype")
		if o.epssData != nil {
			table, err = listGrypeWithEPSS(dst, src, o.epssData)
		} else {
			table, err = ListGrypeReport(dst, src)
		}

	case strings.Contains(inputFilename, "cyclonedx"):
		slog.Debug("list", "filename", inputFilename, "filetype", "cyclonedx")
		if o.epssData != nil {
			table, err = listCyclonedxWithEPSS(dst, src, o.epssData)
		} else {
			table, err = ListCyclonedx(dst, src)
		}

	case strings.Contains(inputFilename, "semgrep"):
		slog.Debug("list", "filename", inputFilename, "filetype", "semgrep")
		table, err = ListSemgrep(dst, src)

	case strings.Contains(inputFilename, "gitleaks"):
		slog.Debug("list", "filename", inputFilename, "filetype", "gitleaks")
		table, err = listGitleaks(dst, src)

	case strings.Contains(inputFilename, "syft"):
		slog.Debug("list", "filename", inputFilename, "filetype", "syft")
		slog.Warn("syft decoder is not supported yet")
		return errors.New("syft not implemented yet")

	case strings.Contains(inputFilename, "bundle") || strings.Contains(inputFilename, "gatecheck"):
		slog.Debug("list", "filename", inputFilename, "filetype", "bundle")
		bundle := archive.NewBundle()
		if err := archive.UntarGzipBundle(src, bundle); err != nil {
			return err
		}
		_, err := fmt.Fprintln(dst, bundle.Content())
		return err

	default:
		slog.Error("unsupported file type, cannot be determined from filename", "filename", inputFilename)
		return errors.New("Failed to list artifact content")
	}

	if err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(o.displayFormat)) {
	case "markdown", "md":
		table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
		table.SetCenterSeparator("|")
		table.SetAutoWrapText(false)
	}

	table.Render()

	return nil
}

func ListGrypeReport(dst io.Writer, src io.Reader) (*tablewriter.Table, error) {
	report := &artifacts.GrypeReportMin{}
	slog.Debug("decode grype report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return nil, err
	}

	catLess := format.NewCatagoricLess([]string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"})
	matrix := format.NewSortableMatrix(make([][]string, 0), 0, catLess)

	for _, item := range report.Matches {
		row := []string{item.Vulnerability.Severity, item.Artifact.Name, item.Artifact.Version, item.Vulnerability.DataSource}
		matrix.Append(row)
	}
	sort.Sort(matrix)

	header := []string{"Grype Severity", "Package", "Version", "Link"}

	table := matrix.Table(dst, header)

	return table, nil
}

func listGrypeWithEPSS(dst io.Writer, src io.Reader, epssData *epss.Data) (*tablewriter.Table, error) {
	report := &artifacts.GrypeReportMin{}
	slog.Debug("decode grype report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return nil, err
	}

	catLess := format.NewCatagoricLess([]string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"})
	matrix := format.NewSortableMatrix(make([][]string, 0), 1, catLess)

	for _, item := range report.Matches {
		cve, ok := epssData.CVEs[item.Vulnerability.ID]
		score := "-"
		prctl := "-"
		if ok {
			score = cve.EPSS
			prctl = cve.Percentile
		}

		row := []string{
			item.Vulnerability.ID,
			item.Vulnerability.Severity,
			score,
			prctl,
			item.Artifact.Name,
			item.Artifact.Version,
			item.Vulnerability.DataSource,
		}
		matrix.Append(row)
	}

	header := []string{
		"Grype CVE ID",
		"Severity",
		"EPSS Score",
		"EPSS Prctl",
		"Package",
		"Version",
		"Link",
	}

	sort.Sort(matrix)

	table := matrix.Table(dst, header)

	return table, nil
}

func ListCyclonedx(dst io.Writer, src io.Reader) (*tablewriter.Table, error) {
	report := &artifacts.CyclonedxReportMin{}
	slog.Debug("decode cyclonedx report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return nil, err
	}

	catLess := format.NewCatagoricLess([]string{"critical", "high", "medium", "low", "none"})
	matrix := format.NewSortableMatrix(make([][]string, 0), 1, catLess)

	link := "-"
	for idx, vul := range report.Vulnerabilities {
		severity := vul.HighestSeverity()
		pkgs := report.AffectedPackages(idx)
		if len(vul.Advisories) > 0 {
			link = vul.Advisories[0].URL
		}
		// get the affected vulnerability
		matrix.Append([]string{vul.ID, severity, pkgs, link})
	}

	sort.Sort(matrix)

	header := []string{"Cyclonedx CVE ID", "Severity", "Package", "Link"}
	table := matrix.Table(dst, header)

	return table, nil
}

func listCyclonedxWithEPSS(dst io.Writer, src io.Reader, epssData *epss.Data) (*tablewriter.Table, error) {
	report := &artifacts.CyclonedxReportMin{}
	slog.Debug("decode grype report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return nil, err
	}

	catLess := format.NewCatagoricLess([]string{"critical", "high", "medium", "low", "info", "none", "unknown"})
	matrix := format.NewSortableMatrix(make([][]string, 0), 1, catLess)

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
		row := []string{
			item.ID,
			item.HighestSeverity(),
			score,
			prctl,
			report.AffectedPackages(idx),
			link,
		}
		matrix.Append(row)
	}

	sort.Sort(matrix)

	header := []string{"Cyclonedx CVE ID", "Severity", "EPSS Score", "EPSS Prctl", "affected Packages", "Link"}
	table := matrix.Table(dst, header)

	return table, nil
}

func ListSemgrep(dst io.Writer, src io.Reader) (*tablewriter.Table, error) {
	report := &artifacts.SemgrepReportMin{}

	if err := json.NewDecoder(src).Decode(report); err != nil {
		return nil, err
	}

	for _, semgrepError := range report.Errors {
		slog.Warn("semgrep runtime error",
			"level", semgrepError.Level,
			"message", semgrepError.ShortMessage(),
			"path", semgrepError.Path,
		)
	}

	catLess := format.NewCatagoricLess([]string{"ERROR", "WARNING", "INFO"})

	matrix := format.NewSortableMatrix(make([][]string, 0), 1, catLess)

	for _, result := range report.Results {
		row := []string{
			result.ShortCheckID(),
			result.Extra.Metadata.OwaspIDs(),
			result.Extra.Severity,
			result.Extra.Metadata.Impact,
			result.Extra.Metadata.Shortlink,
		}
		matrix.Append(row)
	}

	sort.Sort(matrix)

	header := []string{"Semgrep Check ID", "Owasp IDs", "Severity", "Impact", "link"}
	table := matrix.Table(dst, header)

	return table, nil
}

func listGitleaks(dst io.Writer, src io.Reader) (*tablewriter.Table, error) {
	report := &artifacts.GitLeaksReportMin{}
	if err := json.NewDecoder(src).Decode(report); err != nil {
		return nil, err
	}

	table := tablewriter.NewWriter(dst)

	table.SetHeader([]string{"Gitleaks Rule ID", "File", "Commit", "Start Line"})

	for _, finding := range *report {
		row := []string{
			finding.RuleID,
			finding.FileShort(),
			finding.CommitShort(),
			fmt.Sprintf("%d", finding.StartLine),
		}
		table.Append(row)
	}

	if report.Count() == 0 {
		table.SetFooter([]string{"No Gitleaks Findings"})
	}

	return table, nil
}

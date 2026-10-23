package gatecheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/easy-up/go-coverage"
	"io"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	"github.com/olekukonko/tablewriter"
)

// emptyReport means the report listed successfully and has no findings.
// List prints the text and does not render a table.
type emptyReport string

func (e emptyReport) Error() string { return string(e) }

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

func WithEPSS(epssFile *os.File, epssURL string, optionFuncs ...optionFunc) (func(*listOptions), error) {
	data := &epss.Data{}
	f := func(o *listOptions) {
		o.epssData = data
	}

	options := defaultOptions()
	for _, optionFunc := range optionFuncs {
		optionFunc(options)
	}
	if epssURL != "" {
		options.epssURL = epssURL
	}

	if epssFile == nil {
		err := epss.FetchData(data, options.epssDownloadOptions()...)
		return f, err
	}

	err := epss.ParseEPSSDataCSV(epssFile, data)

	return f, err
}

func List(dst io.Writer, src io.Reader, inputFilename string, options ...ListOptionFunc) error {
	table := format.NewTable(dst)
	var err error
	o := &listOptions{}
	for _, f := range options {
		f(o)
	}

	switch {
	case strings.Contains(inputFilename, "grype"):
		slog.Debug("list", "filename", inputFilename, "filetype", "grype")
		if o.epssData != nil {
			err = listGrypeWithEPSS(table, src, o.epssData)
		} else {
			err = ListGrypeReport(table, src)
		}

	case strings.Contains(inputFilename, "cyclonedx"):
		slog.Debug("list", "filename", inputFilename, "filetype", "cyclonedx")
		if o.epssData != nil {
			err = listCyclonedxWithEPSS(table, src, o.epssData)
		} else {
			err = ListCyclonedx(table, src)
		}

	case strings.Contains(inputFilename, "semgrep"):
		slog.Debug("list", "filename", inputFilename, "filetype", "semgrep")
		err = ListSemgrep(table, src)

	case strings.Contains(inputFilename, "gitleaks"):
		slog.Debug("list", "filename", inputFilename, "filetype", "gitleaks")
		err = listGitleaks(table, src)

	case strings.Contains(inputFilename, "trivy"):
		slog.Debug("list", "filename", inputFilename, "filetype", "trivy")
		if o.epssData != nil {
			err = listTrivyWithEPSS(table, src, o.epssData)
		} else {
			err = ListTrivyReport(table, src)
		}

	case strings.Contains(inputFilename, "osv"):
		slog.Debug("list", "filename", inputFilename, "filetype", "osv-scanner")
		if o.epssData != nil {
			err = listOSVWithEPSS(table, src, o.epssData)
		} else {
			err = ListOSVReport(table, src)
		}

	case strings.Contains(inputFilename, "syft"):
		slog.Debug("list", "filename", inputFilename, "filetype", "syft")
		slog.Warn("syft decoder is not supported yet")
		return errors.New("syft not implemented yet")

	case strings.Contains(inputFilename, "bundle") || strings.Contains(inputFilename, "gatecheck"):
		slog.Debug("list", "filename", inputFilename, "filetype", "bundle")
		bundle := archive.NewBundle()
		if err = archive.UntarGzipBundle(src, bundle); err != nil {
			return err
		}
		_, err = fmt.Fprintln(dst, bundle.Content())
		return err

	case artifacts.IsCoverageReport(inputFilename):
		slog.Debug("list", "filename", inputFilename, "filetype", "coverage")

		err = listCoverage(table, inputFilename, src)
	default:
		slog.Error("unsupported file type, cannot be determined from filename", "filename", inputFilename)
		return errors.New("failed to list artifact content")
	}

	if err != nil {
		var empty emptyReport
		if errors.As(err, &empty) {
			_, err = fmt.Fprintln(dst, string(empty))
			return err
		}
		return err
	}

	switch strings.ToLower(strings.TrimSpace(o.displayFormat)) {
	case "markdown", "md":
		format.SetMarkdown(table)
	}

	if err := table.Render(); err != nil {
		return err
	}

	return nil
}

func listCoverage(table *tablewriter.Table, inputFilename string, src io.Reader) error {
	coverageFormat, err := artifacts.GetCoverageMode(inputFilename)
	if err != nil {
		return err
	}

	parser := coverage.New(coverageFormat)
	report, err := parser.ParseReader(src)
	if err != nil {
		return err
	}

	header := []string{"Lines Covered", "Functions Covered", "Branches Covered"}
	table.Header(header)
	if err := table.Append([]string{strconv.Itoa(report.CoveredLines), strconv.Itoa(report.CoveredFunctions), strconv.Itoa(report.CoveredBranches)}); err != nil {
		return err
	}

	lineCoverageStr := fmt.Sprintf("%0.2f%%", (float32(report.CoveredLines)/float32(report.TotalLines))*100)
	funcCoverageStr := fmt.Sprintf("%0.2f%%", (float32(report.CoveredFunctions)/float32(report.TotalFunctions))*100)
	branchCoverageStr := fmt.Sprintf("%0.2f%%", (float32(report.CoveredBranches)/float32(report.TotalBranches))*100)
	table.Footer([]string{lineCoverageStr, funcCoverageStr, branchCoverageStr})

	return nil
}

func ListGrypeReport(table *tablewriter.Table, src io.Reader) error {
	report := &artifacts.GrypeReportMin{}
	slog.Debug("decode grype report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return err
	}

	catLess := format.NewCatagoricLess([]string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"})
	matrix := format.NewSortableMatrix(make([][]string, 0), 0, catLess)

	for _, item := range report.Matches {
		row := []string{item.Vulnerability.Severity, item.Artifact.Name, item.Artifact.Version, item.Vulnerability.DataSource}
		matrix.Append(row)
	}
	sort.Sort(matrix)

	header := []string{"Grype Severity", "Package", "Version", "Link"}

	if len(report.Matches) == 0 {
		return emptyReport("No grype vulnerabilities")
	}

	table.Header(header)
	if err := matrix.Table(table); err != nil {
		return err
	}

	return nil
}

func listGrypeWithEPSS(table *tablewriter.Table, src io.Reader, epssData *epss.Data) error {
	report := &artifacts.GrypeReportMin{}
	slog.Debug("decode grype report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return err
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

	if len(report.Matches) == 0 {
		return emptyReport("No grype vulnerabilities")
	}

	sort.Sort(matrix)

	table.Header(header)
	if err := matrix.Table(table); err != nil {
		return err
	}

	return nil
}

func ListCyclonedx(table *tablewriter.Table, src io.Reader) error {
	report := &artifacts.CyclonedxReportMin{}
	slog.Debug("decode cyclonedx report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return err
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

	if len(report.Vulnerabilities) == 0 {
		return emptyReport("No cyclonedx vulnerabilities")
	}

	sort.Sort(matrix)

	header := []string{"Cyclonedx CVE ID", "Severity", "Package", "Link"}
	table.Header(header)
	if err := matrix.Table(table); err != nil {
		return err
	}

	return nil
}

func listCyclonedxWithEPSS(table *tablewriter.Table, src io.Reader, epssData *epss.Data) error {
	report := &artifacts.CyclonedxReportMin{}
	slog.Debug("decode grype report", "format", "json")
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return err
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

	if len(report.Vulnerabilities) == 0 {
		return emptyReport("No cyclonedx vulnerabilities")
	}

	sort.Sort(matrix)

	header := []string{"Cyclonedx CVE ID", "Severity", "EPSS Score", "EPSS Prctl", "affected Packages", "Link"}
	table.Header(header)
	if err := matrix.Table(table); err != nil {
		return err
	}

	return nil
}

func ListSemgrep(table *tablewriter.Table, src io.Reader) error {
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

	if len(report.Results) == 0 {
		return emptyReport("No semgrep findings")
	}

	sort.Sort(matrix)

	header := []string{"Semgrep Check ID", "Owasp IDs", "Severity", "Impact", "link"}
	table.Header(header)
	if err := matrix.Table(table); err != nil {
		return err
	}

	return nil
}

func listGitleaks(table *tablewriter.Table, src io.Reader) error {
	report := artifacts.GitLeaksReportMin{}
	if err := json.NewDecoder(src).Decode(&report); err != nil {
		return err
	}

	if report.Count() == 0 {
		return emptyReport("No gitleaks findings")
	}

	header := []string{"Gitleaks Rule ID", "File", "Commit", "Start Line"}
	table.Header(header)
	for _, finding := range report {
		row := []string{
			finding.RuleID,
			finding.FileShort(),
			finding.CommitShort(),
			fmt.Sprintf("%d", finding.StartLine),
		}
		if err := table.Append(row); err != nil {
			return err
		}
	}

	return nil
}

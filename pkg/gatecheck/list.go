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
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	"github.com/gatecheckdev/gatecheck/pkg/epss/v1"
	"github.com/gatecheckdev/gatecheck/pkg/format"
)

func List(dst io.Writer, src io.Reader, inputFilename string) error {
	var decoder interface {
		Decode(any) error
	}
	var report interface {
		String() string
	}

	decoder = json.NewDecoder(src)

	switch {
	case strings.Contains(inputFilename, "grype"):
		slog.Debug("list", "filename", inputFilename, "filetype", "grype")
		report = &grype.ScanReport{}

	case strings.Contains(inputFilename, "semgrep"):
		slog.Debug("list", "filename", inputFilename, "filetype", "semgrep")
		report = &semgrep.ScanReport{}

	case strings.Contains(inputFilename, "gitleaks"):
		slog.Debug("list", "filename", inputFilename, "filetype", "gitleaks")
		report = &gitleaks.ScanReport{}

	case strings.Contains(inputFilename, "syft"):
		slog.Debug("list", "filename", inputFilename, "filetype", "syft")
		slog.Warn("syft decoder is not supported yet")
		return nil

	case strings.Contains(inputFilename, "cyclonedx"):
		slog.Debug("list", "filename", inputFilename, "filetype", "cyclonedx")
		report = &cyclonedx.ScanReport{}

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

	if err := decoder.Decode(report); err != nil {
		slog.Error("list decode", "error", err)
		return errors.New("failed to decode report")
	}

	_, err := fmt.Fprintln(dst, report.String())
	return err
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
	if err := epss.FetchData(epssData, fetchOptions); err != nil {
		return err
	}

	var decoder interface {
		Decode(any) error
	}
	decoder = json.NewDecoder(src)

	switch {
	case strings.Contains(inputFilename, "grype"):
		slog.Debug("list all, decode", "filename", inputFilename, "filetype", "grype")
		report := &grype.ScanReport{}
		if err := decoder.Decode(report); err != nil {
			return err
		}
		return listGrypeWithEPSS(dst, report, epssData)

	case strings.Contains(inputFilename, "cyclonedx"):
		slog.Debug("list", "filename", inputFilename, "filetype", "cyclonedx")
		report := &cyclonedx.ScanReport{}
		if err := decoder.Decode(report); err != nil {
			return err
		}
		return listCyclonedxWithEPSS(dst, report, epssData)

	default:
		slog.Error("unsupport file type", "filename", inputFilename)
		return errors.New("failed to list artifact content")
	}
}

func listGrypeWithEPSS(dst io.Writer, report *grype.ScanReport, epssData *epss.Data) error {

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

func listCyclonedxWithEPSS(dst io.Writer, report *cyclonedx.ScanReport, epssData *epss.Data) error {

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

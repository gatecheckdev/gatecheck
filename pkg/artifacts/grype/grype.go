package grype

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/internal/log"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

const ReportType = "Anchore Grype Scan Report"
const ConfigFieldName = "grype"

type ScanReport models.Document

func (r *ScanReport) String() string {
	table := format.NewTable()
	table.AppendRow("Severity", "Package", "Version", "Link")

	for _, item := range r.Matches {
		table.AppendRow(item.Vulnerability.Severity, item.Artifact.Name, item.Artifact.Version, item.Vulnerability.DataSource)
	}

	table.SetSort(0, format.NewCatagoricLess([]string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}))

	sort.Sort(table)

	return format.NewTableWriter(table).String()
}

func (r *ScanReport) RemoveMatches(shouldRemove func(m models.Match) bool) {
	newMatches := make([]models.Match, 0)
	for _, match := range r.Matches {
		if !shouldRemove(match) {
			newMatches = append(newMatches, match)
		}
	}
	r.Matches = newMatches
}

func ByIDs(ids ...string) func(m models.Match) bool {
	return func(m models.Match) bool {
		for _, removeID := range ids {
			if m.Vulnerability.ID == removeID {
				return true
			}
		}
		return false
	}
}

type Config struct {
	AllowList          []ListItem `yaml:"allowList,omitempty" json:"allowList,omitempty"`
	DenyList           []ListItem `yaml:"denyList,omitempty" json:"denyList,omitempty"`
	EPSSAllowThreshold float64    `yaml:"epssAllowThreshold,omitempty" json:"epssAllowThreshold,omitempty"`
	EPSSDenyThreshold  float64    `yaml:"epssDenyThreshold,omitempty" json:"epssDenyThreshold,omitempty"`
	Critical           int        `yaml:"critical"   json:"critical"`
	High               int        `yaml:"high"       json:"high"`
	Medium             int        `yaml:"medium"     json:"medium"`
	Low                int        `yaml:"low"        json:"low"`
	Negligible         int        `yaml:"negligible" json:"negligible"`
	Unknown            int        `yaml:"unknown"    json:"unknown"`
}

type ListItem struct {
	Id     string `yaml:"id"     json:"id"`
	Reason string `yaml:"reason" json:"reason"`
}

func NewReportDecoder() *gce.JSONWriterDecoder[ScanReport] {
	return gce.NewJSONWriterDecoder[ScanReport](ReportType, checkReport)
}

func NewValidator() *gcv.Validator[ScanReport, Config] {
	return gcv.NewValidator[ScanReport, Config](ConfigFieldName, NewReportDecoder(), validateFunc)
}

func checkReport(report *ScanReport) error {
	if report == nil {
		return gce.ErrFailedCheck
	}
	if report.Descriptor.Name != "grype" {
		return fmt.Errorf("%w: Missing Descriptor name", gce.ErrFailedCheck)
	}
	return nil
}

func validateFunc(scanReport ScanReport, config Config) error {

	found := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
	allowed := map[string]int{
		"Critical": config.Critical, "High": config.High, "Medium": config.Medium,
		"Low": config.Low, "Negligible": config.Negligible, "Unknown": config.Unknown,
	}
	foundDenied := make([]models.Match, 0)

LOOPMATCH:
	for matchIndex, match := range scanReport.Matches {

		for _, allowed := range config.AllowList {
			if strings.Compare(match.Vulnerability.ID, allowed.Id) == 0 {

				log.Infof("%s Allowed. Reason: %s", match.Vulnerability.ID, allowed.Reason)
				continue LOOPMATCH
			}
		}

		for _, denied := range config.DenyList {
			if match.Vulnerability.ID == denied.Id {
				log.Infof("%s Denied. Reason: %s", match.Vulnerability.ID, denied.Reason)
				foundDenied = append(foundDenied, scanReport.Matches[matchIndex])
			}
		}

		found[match.Vulnerability.Severity] += 1
	}
	log.Infof("Grype Findings: %v", format.PrettyPrintMap(found))

	var errStrings []string

	for severity := range found {
		// A -1 in config means all allowed
		if allowed[severity] == -1 {
			continue
		}
		if found[severity] > allowed[severity] {
			s := fmt.Sprintf("%s (%d found > %d allowed)", severity, found[severity], allowed[severity])
			errStrings = append(errStrings, s)
		}
	}

	if len(foundDenied) != 0 {
		deniedReport := &ScanReport{Matches: foundDenied}
		errStrings = append(errStrings, fmt.Sprintf("Denied Vulnerabilities\n%s", deniedReport))
	}

	if len(errStrings) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", gcv.ErrValidation, strings.Join(errStrings, ", "))
}

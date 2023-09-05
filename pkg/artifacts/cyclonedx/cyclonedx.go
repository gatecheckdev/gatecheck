// Package cyclonedx provides data model, decoder, and validator for cyclonedx reports
package cyclonedx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"golang.org/x/exp/slices"
)

// ReportType in plain text
const ReportType = "CycloneDX Report"

// ConfigFieldName the field name in the config map
const ConfigFieldName = "cyclonedx"

// ScanReport data model
type ScanReport cdx.BOM

var orderedSeverities = []string{"Critical", "High", "Medium", "Low", "Info", "None", "Unknown"}

// String pretty formatted table
func (r ScanReport) String() string {
	if r.Components == nil {
		return "No Components in Report"
	}

	var sb strings.Builder
	bomTable := format.NewTable()
	bomTable.AppendRow("Name", "Version", "Type", "Ref")

	components := make(map[string]cdx.Component, len(*r.Components))
	for _, item := range *r.Components {
		components[item.BOMRef] = item
		bomTable.AppendRow(item.Name, item.Version, string(item.Type), format.Summarize(item.BOMRef, 50, format.ClipRight))
	}
	if bomTable.Len() > 1 {
		sb.WriteString("CycloneDX SBOM\n")
		sb.WriteString(format.NewTableWriter(bomTable).String())
		sb.WriteString(fmt.Sprintf("Total Components: %d\n\n", len(bomTable.Body())))
	}

	vulTable := format.NewTable()
	vulTable.AppendRow("Severity", "Package", "Version", "Link")
	severities := make(map[string]int)

	for _, vul := range *r.Vulnerabilities {
		severity := string(highestVulnerability(*vul.Ratings).Severity)
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
		vulTable.AppendRow(severity, pkg, version, link)
	}
	vulTable.SetSort(0, format.NewCatagoricLess(orderedSeverities))
	sort.Sort(vulTable)
	if vulTable.Len() > 1 {
		sb.WriteString("CycloneDX Vulnerabilities Report\n")
		sb.WriteString(format.NewTableWriter(vulTable).String())
		sb.WriteString(fmt.Sprintf("Total Vulnerabilities: %d %s\n", len(vulTable.Body()), format.PrettyPrintMap[string, int](severities)))
	}
	return sb.String()
}

func severityIndex(s string) int {
	for index, value := range orderedSeverities {
		if strings.EqualFold(value, s) {
			return index
		}
	}
	return len(orderedSeverities)
}

func highestVulnerability(ratings []cdx.VulnerabilityRating) cdx.VulnerabilityRating {

	sort.Slice(ratings, func(i, j int) bool {
		iIndex, jIndex := severityIndex(string(ratings[i].Severity)), severityIndex(string(ratings[j].Severity))
		return iIndex < jIndex
	})
	return ratings[0]
}

// ReportDecoder Custom decoder to handle multiple report types
type ReportDecoder struct {
	bytes.Buffer
}

// NewReportDecoder ...
func NewReportDecoder() *ReportDecoder {
	return new(ReportDecoder)
}

// Decode and check BOMFormat
func (d *ReportDecoder) Decode() (any, error) {
	report := new(ScanReport)
	err := json.NewDecoder(d).Decode(report)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrEncoding, err)
	}
	if report.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("%w: %v", gce.ErrFailedCheck, "BOMFormat field is not CycloneDX")
	}
	if report.Vulnerabilities == nil {
		report.Vulnerabilities = new([]cdx.Vulnerability)
	}
	if report.Components == nil {
		report.Components = new([]cdx.Component)
	}

	return report, err
}

// DecodeFrom ...
func (d *ReportDecoder) DecodeFrom(r io.Reader) (any, error) {

	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrIO, err)
	}
	return d.Decode()
}

// FileType in plain text
func (d *ReportDecoder) FileType() string {
	return ReportType
}

// Config data model
type Config struct {
	AllowList []ListItem `yaml:"allowList,omitempty" json:"allowList,omitempty"`
	DenyList  []ListItem `yaml:"denyList,omitempty" json:"denyList,omitempty"`
	Required  bool       `yaml:"required" json:"required"`
	Critical  int        `yaml:"critical"   json:"critical"`
	High      int        `yaml:"high"       json:"high"`
	Medium    int        `yaml:"medium"     json:"medium"`
	Low       int        `yaml:"low"        json:"low"`
	Info      int        `yaml:"info"       json:"info"`
	None      int        `yaml:"none"       json:"none"`
	Unknown   int        `yaml:"unknown"    json:"unknown"`
}

// ListItem for a specific allow/deny list record
type ListItem struct {
	ID     string `yaml:"id"     json:"id"`
	Reason string `yaml:"reason" json:"reason"`
}

// NewValidator implementation of the generic validator
func NewValidator() gcv.Validator[cdx.Vulnerability, Config] {
	validator := gcv.NewValidator[cdx.Vulnerability, Config]()
	validator = validator.WithValidationRules(ThresholdRule, DenyListRule)
	validator = validator.WithAllowRules(AllowListRule)
	return validator
}

// ThresholdRule deny if X > vulnerabilities of Y Severity
func ThresholdRule(vuls []cdx.Vulnerability, config Config) error {
	orderedKeys := []string{"Critical", "High", "Medium", "Low", "Info", "None", "Unknown"}
	allowed := map[string]int{
		"Critical": config.Critical,
		"High":     config.High,
		"Medium":   config.Medium,
		"Low":      config.Low,
		"Info":     config.Info,
		"None":     config.None,
		"Unknown":  config.Unknown,
	}

	found := make(map[string]int, 7)
	for severity := range allowed {
		found[severity] = 0
	}

	for _, vul := range vuls {
		severity := strings.ToLower(string(highestVulnerability(*vul.Ratings).Severity))
		severity = strings.ToUpper(severity[:1]) + severity[1:]
		found[severity]++
	}

	var errs error
	for severity, allowThreshold := range allowed {
		if allowThreshold == -1 {
			continue
		}
		if found[severity] > allowThreshold {
			rule := fmt.Sprintf("%s allowed %d found", severity, allowThreshold)
			errs = errors.Join(errs, gcv.NewFailedRuleError(rule, fmt.Sprint(found[severity])))
		}
	}

	foundStr := format.PrettyPrintMapOrdered(found, orderedKeys)
	allowedStr := format.PrettyPrintMapOrdered(allowed, orderedKeys)
	slog.Debug("cyclonedx threshold validation", "allowed", allowedStr, "found", foundStr)

	return errs
}

// AllowListRule for custom list
func AllowListRule(vul cdx.Vulnerability, config Config) bool {
	return slices.ContainsFunc(config.AllowList, func(allowListItem ListItem) bool {
		return strings.EqualFold(vul.ID, allowListItem.ID)
	})
}

// DenyListRule for custom list
func DenyListRule(vuls []cdx.Vulnerability, config Config) error {
	slog.Debug("cyclonedx custom deny list rule")
	return gcv.DenyFunc(vuls, func(vul cdx.Vulnerability) error {
		inDenyList := slices.ContainsFunc(config.DenyList, func(allowListItem ListItem) bool {
			return strings.EqualFold(vul.ID, allowListItem.ID)
		})
		if !inDenyList {
			return nil
		}
		return gcv.NewFailedRuleError("CycloneDX Custom DenyList Rule", vul.ID)
	})
}

// ShimComponentsAsVulnerabilities modify the report to add compontents as vulnerabilities with no score
func (r *ScanReport) ShimComponentsAsVulnerabilities() *ScanReport {
	nv := cdx.Vulnerability{
		ID: "",
		Ratings: &[]cdx.VulnerabilityRating{
			{
				Severity: cdx.SeverityNone,
			},
		},
		Description:    " ",
		Recommendation: " ",
		Analysis: &cdx.VulnerabilityAnalysis{
			State:  cdx.IASNotAffected,
			Detail: "Gatecheck added to be reported as a component of the product.",
		},
		Affects: &[]cdx.Affects{},
	}
	for _, c := range *r.Components {
		*nv.Affects = append(*nv.Affects, cdx.Affects{Ref: c.BOMRef})
	}
	*r.Vulnerabilities = append(*r.Vulnerabilities, nv)
	return r
}

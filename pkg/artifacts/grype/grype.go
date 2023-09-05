// Package grype defines data model, Config, Decoder, Validator, and validation rules for Anchore Grype vulnerability reports.
package grype

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"github.com/anchore/grype/grype/presenter/models"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"golang.org/x/exp/slices"
)

// ReportType the Grype Type plain text
const ReportType = "Anchore Grype Scan Report"

// ConfigFieldName ...
const ConfigFieldName = "grype"

// ScanReport data model for grype reports aliased from grype code base
type ScanReport models.Document

// String ...
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

// Config data model for grype thresholds configuration
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

// ListItem for Allow/Deny list
type ListItem struct {
	ID     string `yaml:"id"     json:"id"`
	Reason string `yaml:"reason" json:"reason"`
}

// NewReportDecoder ...
func NewReportDecoder() *gce.JSONWriterDecoder[ScanReport] {
	return gce.NewJSONWriterDecoder[ScanReport](ReportType, checkReport)
}

// NewValidator ...
func NewValidator() gcv.Validator[models.Match, Config] {
	validator := gcv.NewValidator[models.Match, Config]()
	validator = validator.WithAllowRules(AllowListRule)
	validator = validator.WithValidationRules(ThresholdRule, DenyListRule)
	return validator
}

// ThresholdRule will error if there are more vulnerabilities in X severity
func ThresholdRule(matches []models.Match, config Config) error {
	orderedKeys := []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
	allowed := map[string]int{
		orderedKeys[0]: config.Critical,
		orderedKeys[1]: config.High,
		orderedKeys[2]: config.Medium,
		orderedKeys[3]: config.Low,
		orderedKeys[4]: config.Negligible,
		orderedKeys[5]: config.Unknown,
	}
	slog.Debug("grype threshold validation", "allowed", format.PrettyPrintMapOrdered(allowed, orderedKeys))

	found := make(map[string]int, 6)
	for severity := range allowed {
		found[severity] = 0
	}

	for _, match := range matches {
		found[match.Vulnerability.Severity]++
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
	slog.Debug("grype threshold validation", "found", format.PrettyPrintMapOrdered(found, orderedKeys))
	return errs
}

// DenyListRule reject vulnerabilities in custom deny list
func DenyListRule(matches []models.Match, config Config) error {
	slog.Debug("grype custom deny list validation")
	return gcv.DenyFunc(matches, func(m models.Match) error {
		inDenyList := slices.ContainsFunc(config.DenyList, func(denyListItem ListItem) bool {
			return m.Vulnerability.ID == denyListItem.ID
		})
		if !inDenyList {
			return nil
		}
		return gcv.NewFailedRuleError("Grype Custom DenyList Rule", m.Vulnerability.ID)
	})
}

// AllowListRule allow vulnerabilities in custom allow list
func AllowListRule(match models.Match, config Config) bool {
	return slices.ContainsFunc(config.AllowList, func(allowedItem ListItem) bool {
		return match.Vulnerability.ID == allowedItem.ID
	})
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

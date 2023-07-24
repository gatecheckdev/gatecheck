package grype

import (
	"errors"
	"fmt"
	"sort"

	"github.com/anchore/grype/grype/presenter/models"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"golang.org/x/exp/slices"
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

func NewValidator() gcv.Validator[models.Match, Config] {
	validator := gcv.NewValidator[models.Match, Config]()
	validator = validator.WithAllowRules(AllowListRule)
	validator = validator.WithValidationRules(ThresholdRule, DenyListRule)
	return validator
}

func ThresholdRule(matches []models.Match, config Config) error {
	allowed := map[string]int{
		"Critical":   config.Critical,
		"High":       config.High,
		"Medium":     config.Medium,
		"Low":        config.Low,
		"Negligible": config.Negligible,
		"Unknown":    config.Unknown,
	}

	found := make(map[string]int, 6)
	for severity := range allowed {
		found[severity] = 0
	}

	for _, match := range matches {
		found[match.Vulnerability.Severity] += 1
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
	return errs
}

func DenyListRule(matches []models.Match, config Config) error {
	return gcv.ValidateFunc(matches, func(m models.Match) error {
		inDenyList := slices.ContainsFunc(config.DenyList, func(denyListItem ListItem) bool {
			return m.Vulnerability.ID == denyListItem.Id
		})
		if !inDenyList {
			return nil
		}
		return gcv.NewFailedRuleError("Custom DenyList", m.Vulnerability.ID)
	})
}

func AllowListRule(match models.Match, config Config) bool {
	return slices.ContainsFunc(config.AllowList, func(allowedItem ListItem) bool {
		return match.Vulnerability.ID == allowedItem.Id
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

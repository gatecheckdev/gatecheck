package artifacts

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// SarifReport is the subset of SARIF 2.1.0 used for listing and validation.
type SarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

// SarifRun is one tool invocation inside a SARIF report.
type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

// SarifTool is the tool that produced a run.
type SarifTool struct {
	Driver     SarifDriver   `json:"driver"`
	Extensions []SarifDriver `json:"extensions"`
}

// SarifDriver is a SARIF tool component that owns rules.
type SarifDriver struct {
	Name  string      `json:"name"`
	Rules []SarifRule `json:"rules"`
}

// SarifRule is a SARIF reporting descriptor.
type SarifRule struct {
	ID                   string         `json:"id"`
	DefaultConfiguration *SarifConfig   `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

// SarifConfig is a rule's default reporting configuration.
type SarifConfig struct {
	Level string `json:"level"`
}

// SarifResult is one SARIF result.
type SarifResult struct {
	RuleID        string            `json:"ruleId"`
	RuleIndex     *int              `json:"ruleIndex"`
	Level         string            `json:"level"`
	Kind          string            `json:"kind"`
	Message       SarifMessage      `json:"message"`
	Locations     []SarifLocation   `json:"locations"`
	Properties    map[string]any    `json:"properties"`
	Suppressions  []json.RawMessage `json:"suppressions"`
	BaselineState string            `json:"baselineState"`
}

// SarifMessage is a SARIF message object.
type SarifMessage struct {
	Text string `json:"text"`
}

// SarifLocation is a SARIF location.
type SarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// SarifFinding is one result that list and validate count.
type SarifFinding struct {
	RuleID   string
	Severity string
	URI      string
	Line     int
	Tool     string
}

// Location is the file and start line, or "-" when the result has neither.
func (f SarifFinding) Location() string {
	switch {
	case f.URI == "" && f.Line <= 0:
		return "-"
	case f.Line <= 0:
		return f.URI
	default:
		return fmt.Sprintf("%s:%d", f.URI, f.Line)
	}
}

// Findings returns the results that list and validate count.
// Suppressed results, passes, and results marked absent in a baseline are omitted.
// The report version must be 2.1.0.
func (r *SarifReport) Findings() ([]SarifFinding, error) {
	if r.Version != "2.1.0" {
		return nil, fmt.Errorf("unsupported SARIF version %q", r.Version)
	}

	findings := make([]SarifFinding, 0)
	for _, run := range r.Runs {
		rules := run.rules()
		tool := run.Tool.Driver.Name
		for _, result := range run.Results {
			if !result.counted() {
				continue
			}
			rule := findRule(rules, result)
			findings = append(findings, SarifFinding{
				RuleID:   result.ruleID(rule),
				Severity: result.severity(rule),
				URI:      result.uri(),
				Line:     result.line(),
				Tool:     tool,
			})
		}
	}
	return findings, nil
}

func (run SarifRun) rules() []SarifRule {
	rules := make([]SarifRule, 0, len(run.Tool.Driver.Rules))
	rules = append(rules, run.Tool.Driver.Rules...)
	for _, ext := range run.Tool.Extensions {
		rules = append(rules, ext.Rules...)
	}
	return rules
}

func findRule(rules []SarifRule, result SarifResult) *SarifRule {
	if result.RuleID != "" {
		for i := range rules {
			if rules[i].ID == result.RuleID {
				return &rules[i]
			}
		}
		for i := range rules {
			if strings.EqualFold(rules[i].ID, result.RuleID) {
				return &rules[i]
			}
		}
	}
	if result.RuleIndex != nil && *result.RuleIndex >= 0 && *result.RuleIndex < len(rules) {
		return &rules[*result.RuleIndex]
	}
	return nil
}

func (result SarifResult) ruleID(rule *SarifRule) string {
	if result.RuleID != "" {
		return result.RuleID
	}
	if rule != nil {
		return rule.ID
	}
	return ""
}

func (result SarifResult) uri() string {
	if len(result.Locations) == 0 {
		return ""
	}
	return result.Locations[0].PhysicalLocation.ArtifactLocation.URI
}

func (result SarifResult) line() int {
	if len(result.Locations) == 0 {
		return 0
	}
	return result.Locations[0].PhysicalLocation.Region.StartLine
}

// counted reports whether list and validate include the result.
func (result SarifResult) counted() bool {
	switch strings.ToLower(result.Kind) {
	case "pass", "notapplicable":
		return false
	}
	if strings.EqualFold(result.Level, "none") {
		return false
	}
	if len(result.Suppressions) > 0 {
		return false
	}
	if strings.EqualFold(result.BaselineState, "absent") {
		return false
	}
	return true
}

// severity maps security-severity, then SARIF level, onto critical, high, medium, low, or none.
// security-severity on the result wins, then security-severity on the rule.
// A missing level uses the rule default, then "warning", which is the SARIF default.
func (result SarifResult) severity(rule *SarifRule) string {
	if score, ok := securitySeverity(result.Properties); ok {
		return severityFromSecurityScore(score)
	}
	if rule != nil {
		if score, ok := securitySeverity(rule.Properties); ok {
			return severityFromSecurityScore(score)
		}
	}
	level := result.Level
	if level == "" && rule != nil && rule.DefaultConfiguration != nil {
		level = rule.DefaultConfiguration.Level
	}
	if level == "" {
		level = "warning"
	}
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	case "none":
		return "none"
	default:
		return "medium"
	}
}

func securitySeverity(props map[string]any) (float64, bool) {
	if len(props) == 0 {
		return 0, false
	}
	value, ok := props["security-severity"]
	if !ok || value == nil {
		return 0, false
	}
	switch n := value.(type) {
	case float64:
		return n, true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	case json.Number:
		parsed, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

// severityFromSecurityScore uses the GitHub code scanning ranges for security-severity.
func severityFromSecurityScore(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

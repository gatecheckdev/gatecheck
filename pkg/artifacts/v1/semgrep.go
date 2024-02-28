package artifacts

import (
	"fmt"
	"log/slog"
	"strings"
)

type SemgrepReportMin struct {
	Version string           `json:"version"`
	Errors  []semgrepError   `json:"errors"`
	Results []SemgrepResults `json:"results"`
}

type semgrepError struct {
	Level   string `json:"level"`
	Message string `json:"message"`
	Path    string `json:"path"`
}

type SemgrepResults struct {
	Extra   semgrepExtra `json:"extra"`
	CheckID string       `json:"check_id"`
}

type semgrepExtra struct {
	Severity string          `json:"severity"`
	Metadata semgrepMetadata `json:"metadata"`
	Message  string          `json:"message"`
}

type semgrepMetadata struct {
	Category   string   `json:"category"`
	Confidence string   `json:"confidence"`
	CWE        []string `json:"cwe"`
	Impact     string   `json:"impact"`
	Likelihood string   `json:"likelihood"`
	Shortlink  string   `json:"shortlink"`
	Owasp      any      `json:"owasp"`
}

func (s *SemgrepReportMin) SelectBySeverity(severity string) []SemgrepResults {
	results := []SemgrepResults{}
	for _, result := range s.Results {
		if strings.EqualFold(result.Extra.Severity, severity) {
			results = append(results, result)
		}
	}
	return results
}

func (s *semgrepError) ShortMessage() string {
	parts := strings.Split(s.Message, "\n")
	if len(parts) == 0 {
		return "-"
	}
	return parts[0]
}

func (s *SemgrepResults) ShortCheckID() string {
	parts := strings.Split(s.CheckID, ".")
	switch len(parts) {
	case 0:
		return "-"
	case 1, 2, 3:
		return s.CheckID
	}

	return fmt.Sprintf("%s...%s", parts[0], parts[len(parts)-1])
}

func (s *semgrepMetadata) OwaspIDs() string {
	slog.Info(s.Shortlink, "type", fmt.Sprintf("%T", s.Owasp))
	switch v := s.Owasp.(type) {
	case string:
		return v
	case []interface{}:
		ids := []string{}
		for _, id := range v {
			ids = append(ids, fmt.Sprintf("%v", id))
		}
		return strings.Join(ids, ", ")
	default:
		return "-"
	}
}

package gatecheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
	"github.com/olekukonko/tablewriter"
)

// configScorecard gates an OpenSSF Scorecard JSON report.
type configScorecard struct {
	Enabled bool `json:"enabled" toml:"enabled" yaml:"enabled"`
	// MinScore fails the report when the aggregate score is lower. 0 to 10.
	MinScore float64 `json:"minScore" toml:"minScore" yaml:"minScore"`
	// Checks set a minimum for individual checks, by check name.
	Checks []configScorecardCheck `json:"checks" toml:"checks" yaml:"checks"`
}

type configScorecardCheck struct {
	Name     string  `json:"name"     toml:"name"     yaml:"name"`
	MinScore float64 `json:"minScore" toml:"minScore" yaml:"minScore"`
}

// configTrufflehog gates trufflehog --json output.
type configTrufflehog struct {
	// LimitEnabled fails the report when it has any finding.
	LimitEnabled bool `json:"limitEnabled" toml:"limitEnabled" yaml:"limitEnabled"`
	// VerifiedOnly counts only secrets trufflehog verified as live.
	VerifiedOnly bool `json:"verifiedOnly" toml:"verifiedOnly" yaml:"verifiedOnly"`
}

func decodeScorecard(src io.Reader) (*artifacts.ScorecardReport, error) {
	report := &artifacts.ScorecardReport{}
	if err := json.NewDecoder(src).Decode(report); err != nil {
		return nil, err
	}
	return report, nil
}

func listScorecard(table *tablewriter.Table, src io.Reader) error {
	report, err := decodeScorecard(src)
	if err != nil {
		return err
	}
	if len(report.Checks) == 0 {
		return emptyReport("No scorecard checks")
	}
	checks := append([]artifacts.ScorecardCheck(nil), report.Checks...)
	sort.SliceStable(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })
	table.Header([]string{"Scorecard Check", "Score", "Reason"})
	for _, c := range checks {
		if err := table.Append([]string{c.Name, scoreText(c.Score), c.Reason}); err != nil {
			return err
		}
	}
	table.Footer([]string{report.Repo.Name, scoreText(report.Score), "aggregate"})
	return nil
}

func scoreText(score float64) string {
	if score < 0 {
		return "?"
	}
	return fmt.Sprintf("%g", score)
}

func validateScorecardReport(src io.Reader, config *Config) error {
	report, err := decodeScorecard(src)
	if err != nil {
		slog.Error("decode scorecard report for validation", "error", err)
		return errors.New("cannot run Scorecard validation: Report decoding failed, See log for details")
	}
	return ruleScorecard(config, report)
}

func ruleScorecard(config *Config, report *artifacts.ScorecardReport) error {
	cfg := config.Scorecard
	if !cfg.Enabled {
		slog.Debug("scorecard limits not enabled", "score", report.Score)
		return nil
	}
	var failures []string
	switch {
	case report.Score < 0:
		slog.Warn("scorecard aggregate score is inconclusive", "repo", report.Repo.Name)
	case report.Score < cfg.MinScore:
		slog.Error("scorecard aggregate score below minimum", "repo", report.Repo.Name, "score", report.Score, "min_score", cfg.MinScore)
		failures = append(failures, "aggregate")
	default:
		slog.Info("scorecard aggregate score valid", "repo", report.Repo.Name, "score", report.Score, "min_score", cfg.MinScore)
	}

	byName := map[string]artifacts.ScorecardCheck{}
	for _, c := range report.Checks {
		byName[strings.ToLower(c.Name)] = c
	}
	for _, want := range cfg.Checks {
		got, ok := byName[strings.ToLower(want.Name)]
		switch {
		case !ok:
			slog.Warn("scorecard check not in report", "check", want.Name)
		case got.Inconclusive():
			slog.Warn("scorecard check is inconclusive, not checked", "check", got.Name, "reason", got.Reason)
		case got.Score < want.MinScore:
			slog.Error("scorecard check below minimum", "check", got.Name, "score", got.Score, "min_score", want.MinScore, "reason", got.Reason)
			failures = append(failures, got.Name)
		default:
			slog.Info("scorecard check valid", "check", got.Name, "score", got.Score, "min_score", want.MinScore)
		}
	}
	if len(failures) > 0 {
		return newValidationErr("Scorecard: score below minimum for " + strings.Join(failures, ", "))
	}
	return nil
}

func listTrufflehog(table *tablewriter.Table, src io.Reader) error {
	content, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	findings, err := artifacts.DecodeTrufflehog(content)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return emptyReport("No trufflehog findings")
	}
	table.Header([]string{"Trufflehog Detector", "Verified", "Location", "Commit"})
	for _, f := range findings {
		verified := "no"
		if f.Verified {
			verified = "yes"
		}
		if err := table.Append([]string{f.DetectorName, verified, f.Location(), f.Commit()}); err != nil {
			return err
		}
	}
	return nil
}

func validateTrufflehogReport(src io.Reader, config *Config) error {
	content, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	findings, err := artifacts.DecodeTrufflehog(content)
	if err != nil {
		slog.Error("decode trufflehog report for validation", "error", err)
		return errors.New("cannot run Trufflehog validation: Report decoding failed, See log for details")
	}
	cfg := config.Trufflehog
	if !cfg.LimitEnabled {
		slog.Debug("secrets limit not enabled", "artifact", "trufflehog", "findings", len(findings))
		return nil
	}
	var counted int
	for _, f := range findings {
		if cfg.VerifiedOnly && !f.Verified {
			continue
		}
		counted++
		slog.Warn("secret detected", "artifact", "trufflehog", "detector", f.DetectorName, "verified", f.Verified, "location", f.Location())
	}
	if counted > 0 {
		slog.Error("committed secrets violation", "artifact", "trufflehog", "secrets_detected", counted, "verified_only", cfg.VerifiedOnly)
		return newValidationErr("Trufflehog: Secrets Detected")
	}
	slog.Info("secrets limit valid", "artifact", "trufflehog", "findings", len(findings), "verified_only", cfg.VerifiedOnly)
	return nil
}

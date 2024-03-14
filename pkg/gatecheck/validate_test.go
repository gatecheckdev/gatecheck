package gatecheck

import (
	"os"
	"testing"
	"time"

	"log/slog"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/v1"
	"github.com/lmittmann/tint"
)

func TestMain(m *testing.M) {
	h := tint.NewHandler(os.Stderr, &tint.Options{
		AddSource:  true,
		Level:      slog.LevelDebug,
		TimeFormat: time.TimeOnly,
	})
	slog.SetDefault(slog.New(h))
	os.Exit(m.Run())
}

func Test_ruleGrypeSeverityLimit(t *testing.T) {
	t.Run("empty-report-empty-config", func(t *testing.T) {
		config := new(Config)
		report := new(artifacts.GrypeReportMin)

		want := true
		got := ruleGrypeSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("empty-report-limit-0", func(t *testing.T) {
		config := new(Config)
		config.Grype.SeverityLimit.Critical.Enabled = true
		config.Grype.SeverityLimit.Critical.Limit = 0
		report := new(artifacts.GrypeReportMin)

		want := true
		got := ruleGrypeSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("violate-limit", func(t *testing.T) {
		config := new(Config)
		config.Grype.SeverityLimit.Critical.Enabled = true
		config.Grype.SeverityLimit.Critical.Limit = 0
		report := new(artifacts.GrypeReportMin)
		report.Matches = []artifacts.GrypeMatch{
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "critical"}},
		}

		want := false
		got := ruleGrypeSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("violate-limit-all-severities-1", func(t *testing.T) {
		config := new(Config)
		config.Grype.SeverityLimit.Critical.Enabled = true
		config.Grype.SeverityLimit.Critical.Limit = 0
		config.Grype.SeverityLimit.High.Enabled = true
		config.Grype.SeverityLimit.High.Limit = 0
		config.Grype.SeverityLimit.Medium.Enabled = true
		config.Grype.SeverityLimit.Medium.Limit = 0
		config.Grype.SeverityLimit.Low.Enabled = true
		config.Grype.SeverityLimit.Low.Limit = 0

		report := new(artifacts.GrypeReportMin)
		report.Matches = []artifacts.GrypeMatch{
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "critical"}},
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "high"}},
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "medium"}},
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "low"}},
		}

		want := false
		got := ruleGrypeSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("violate-limit-all-severities-2", func(t *testing.T) {
		config := new(Config)
		config.Grype.SeverityLimit.Critical.Enabled = true
		config.Grype.SeverityLimit.Critical.Limit = 1
		config.Grype.SeverityLimit.High.Enabled = true
		config.Grype.SeverityLimit.High.Limit = 1
		config.Grype.SeverityLimit.Medium.Enabled = true
		config.Grype.SeverityLimit.Medium.Limit = 1
		config.Grype.SeverityLimit.Low.Enabled = true
		config.Grype.SeverityLimit.Low.Limit = 1

		report := new(artifacts.GrypeReportMin)
		report.Matches = []artifacts.GrypeMatch{
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "critical"}},
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "high"}},
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "medium"}},
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "low"}},
		}

		want := true
		got := ruleGrypeSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("violate-limit-all-severities-3", func(t *testing.T) {
		config := new(Config)
		config.Grype.SeverityLimit.Critical.Enabled = true
		config.Grype.SeverityLimit.Critical.Limit = 1
		config.Grype.SeverityLimit.High.Enabled = true
		config.Grype.SeverityLimit.High.Limit = 0
		config.Grype.SeverityLimit.Medium.Enabled = true
		config.Grype.SeverityLimit.Medium.Limit = 1
		config.Grype.SeverityLimit.Low.Enabled = true
		config.Grype.SeverityLimit.Low.Limit = 0

		report := new(artifacts.GrypeReportMin)
		report.Matches = []artifacts.GrypeMatch{
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "critical"}},
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "high"}},
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "medium"}},
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "low"}},
		}

		want := false
		got := ruleGrypeSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("violate-limit-accepted", func(t *testing.T) {
		config := new(Config)
		config.Grype.SeverityLimit.Critical.Enabled = true
		config.Grype.SeverityLimit.Critical.Limit = 0
		config.Grype.CVERiskAcceptance.Enabled = true
		config.Grype.CVERiskAcceptance.CVEs = []configCVE{{ID: "cve-1"}}
		report := new(artifacts.GrypeReportMin)
		report.Matches = []artifacts.GrypeMatch{
			{Vulnerability: artifacts.GrypeVulnerability{Severity: "critical", ID: "cve-1"}},
		}

		want := true
		got := false
		err := validateGrypeRules(config, report, nil, nil)
		if err == nil {
			got = true
		}

		if want != got {
			t.Fatalf("want: %t got: %t error: %v", want, got, err)
		}
	})
}

func Test_ruleCyclonedxSeverityLimit(t *testing.T) {
	t.Run("empty-report-empty-config", func(t *testing.T) {
		config := new(Config)
		report := new(artifacts.CyclonedxReportMin)

		want := true
		got := ruleCyclonedxSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("empty-report-limit-0", func(t *testing.T) {
		config := new(Config)
		config.Cyclonedx.SeverityLimit.Critical.Enabled = true
		config.Cyclonedx.SeverityLimit.Critical.Limit = 0
		report := new(artifacts.CyclonedxReportMin)

		want := true
		got := ruleCyclonedxSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("violate-limit", func(t *testing.T) {
		config := new(Config)
		config.Cyclonedx.SeverityLimit.Critical.Enabled = true
		config.Cyclonedx.SeverityLimit.Critical.Limit = 0
		report := new(artifacts.CyclonedxReportMin)
		report.Vulnerabilities = []artifacts.CyclonedxVulnerability{
			{Ratings: []artifacts.CyclonedxRating{{Severity: "critical"}}},
		}

		want := false
		got := ruleCyclonedxSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("violate-limit-all-severities-1", func(t *testing.T) {
		config := new(Config)
		config.Cyclonedx.SeverityLimit.Critical.Enabled = true
		config.Cyclonedx.SeverityLimit.Critical.Limit = 0
		config.Cyclonedx.SeverityLimit.High.Enabled = true
		config.Cyclonedx.SeverityLimit.High.Limit = 0
		config.Cyclonedx.SeverityLimit.Medium.Enabled = true
		config.Cyclonedx.SeverityLimit.Medium.Limit = 0
		config.Cyclonedx.SeverityLimit.Low.Enabled = true
		config.Cyclonedx.SeverityLimit.Low.Limit = 0

		report := new(artifacts.CyclonedxReportMin)
		report.Vulnerabilities = []artifacts.CyclonedxVulnerability{
			{Ratings: []artifacts.CyclonedxRating{{Severity: "critical"}}},
			{Ratings: []artifacts.CyclonedxRating{{Severity: "high"}}},
			{Ratings: []artifacts.CyclonedxRating{{Severity: "medium"}}},
			{Ratings: []artifacts.CyclonedxRating{{Severity: "low"}}},
		}

		want := false
		got := ruleCyclonedxSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("violate-limit-all-severities-2", func(t *testing.T) {
		config := new(Config)
		config.Cyclonedx.SeverityLimit.Critical.Enabled = true
		config.Cyclonedx.SeverityLimit.Critical.Limit = 1
		config.Cyclonedx.SeverityLimit.High.Enabled = true
		config.Cyclonedx.SeverityLimit.High.Limit = 1
		config.Cyclonedx.SeverityLimit.Medium.Enabled = true
		config.Cyclonedx.SeverityLimit.Medium.Limit = 1
		config.Cyclonedx.SeverityLimit.Low.Enabled = true
		config.Cyclonedx.SeverityLimit.Low.Limit = 1

		report := new(artifacts.CyclonedxReportMin)
		report.Vulnerabilities = []artifacts.CyclonedxVulnerability{
			{Ratings: []artifacts.CyclonedxRating{{Severity: "critical"}}},
			{Ratings: []artifacts.CyclonedxRating{{Severity: "high"}}},
			{Ratings: []artifacts.CyclonedxRating{{Severity: "medium"}}},
			{Ratings: []artifacts.CyclonedxRating{{Severity: "low"}}},
		}

		want := true
		got := ruleCyclonedxSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("violate-limit-all-severities-3", func(t *testing.T) {
		config := new(Config)
		config.Cyclonedx.SeverityLimit.Critical.Enabled = true
		config.Cyclonedx.SeverityLimit.Critical.Limit = 1
		config.Cyclonedx.SeverityLimit.High.Enabled = true
		config.Cyclonedx.SeverityLimit.High.Limit = 0
		config.Cyclonedx.SeverityLimit.Medium.Enabled = true
		config.Cyclonedx.SeverityLimit.Medium.Limit = 1
		config.Cyclonedx.SeverityLimit.Low.Enabled = true
		config.Cyclonedx.SeverityLimit.Low.Limit = 0

		report := new(artifacts.CyclonedxReportMin)
		report.Vulnerabilities = []artifacts.CyclonedxVulnerability{
			{Ratings: []artifacts.CyclonedxRating{{Severity: "critical"}}},
			{Ratings: []artifacts.CyclonedxRating{{Severity: "high"}}},
			{Ratings: []artifacts.CyclonedxRating{{Severity: "medium"}}},
			{Ratings: []artifacts.CyclonedxRating{{Severity: "low"}}},
		}

		want := false
		got := ruleCyclonedxSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("violate-limit-accepted", func(t *testing.T) {
		config := new(Config)
		config.Cyclonedx.SeverityLimit.Critical.Enabled = true
		config.Cyclonedx.SeverityLimit.Critical.Limit = 0
		config.Cyclonedx.CVERiskAcceptance.Enabled = true
		config.Cyclonedx.CVERiskAcceptance.CVEs = []configCVE{{ID: "cve-1"}}
		report := new(artifacts.CyclonedxReportMin)
		report.Vulnerabilities = []artifacts.CyclonedxVulnerability{
			{
				Ratings: []artifacts.CyclonedxRating{{Severity: "critical"}},
				ID:      "cve-1",
			},
		}

		want := true
		got := false
		err := validateCyclonedxRules(config, report, nil, nil)
		if err == nil {
			got = true
		}

		if want != got {
			t.Fatalf("want: %t got: %t error: %v", got, err, err)
		}
	})
}

func Test_ruleSemgrepSeverityLimit(t *testing.T) {

	t.Run("empty-report-empty-config", func(t *testing.T) {
		config := new(Config)
		report := new(artifacts.SemgrepReportMin)

		want := true

		got := ruleSemgrepSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("empty-report-limit-0", func(t *testing.T) {
		config := new(Config)
		config.Semgrep.SeverityLimit.Error.Enabled = true
		config.Semgrep.SeverityLimit.Error.Limit = 0
		report := new(artifacts.SemgrepReportMin)

		want := true

		got := ruleSemgrepSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("violate-limit-all", func(t *testing.T) {
		config := new(Config)
		config.Semgrep.SeverityLimit.Error.Enabled = true
		config.Semgrep.SeverityLimit.Error.Limit = 0
		config.Semgrep.SeverityLimit.Warning.Enabled = true
		config.Semgrep.SeverityLimit.Warning.Limit = 10
		config.Semgrep.SeverityLimit.Info.Enabled = true
		config.Semgrep.SeverityLimit.Info.Limit = 2
		report := new(artifacts.SemgrepReportMin)

		report.Results = []artifacts.SemgrepResults{
			{Extra: artifacts.SemgrepExtra{Severity: "error"}},
			{Extra: artifacts.SemgrepExtra{Severity: "error"}},
			{Extra: artifacts.SemgrepExtra{Severity: "warning"}},
			{Extra: artifacts.SemgrepExtra{Severity: "info"}},
			{Extra: artifacts.SemgrepExtra{Severity: "info"}},
			{Extra: artifacts.SemgrepExtra{Severity: "info"}},
		}

		want := false

		got := ruleSemgrepSeverityLimit(config, report)

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}
	})

	t.Run("impact-risk-acceptance-1", func(t *testing.T) {
		config := new(Config)
		config.Semgrep.SeverityLimit.Error.Enabled = true
		config.Semgrep.SeverityLimit.Error.Limit = 0
		config.Semgrep.ImpactRiskAcceptance.Enabled = true
		config.Semgrep.ImpactRiskAcceptance.Low = true
		report := new(artifacts.SemgrepReportMin)

		report.Results = []artifacts.SemgrepResults{
			{Extra: artifacts.SemgrepExtra{Severity: "error", Metadata: artifacts.SemgrepMetadata{Impact: "low"}}},
			{Extra: artifacts.SemgrepExtra{Severity: "error", Metadata: artifacts.SemgrepMetadata{Impact: "low"}}},
			{Extra: artifacts.SemgrepExtra{Severity: "error", Metadata: artifacts.SemgrepMetadata{Impact: "low"}}},
			{Extra: artifacts.SemgrepExtra{Severity: "error", Metadata: artifacts.SemgrepMetadata{Impact: "low"}}},
		}

		want := true
		got := true

		err := validateSemgrepRules(config, report)
		if err != nil {
			got = false
		}

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}

	})

	t.Run("impact-risk-acceptance-2", func(t *testing.T) {
		config := new(Config)
		config.Semgrep.SeverityLimit.Error.Enabled = true
		config.Semgrep.SeverityLimit.Error.Limit = 0
		config.Semgrep.ImpactRiskAcceptance.Enabled = true
		config.Semgrep.ImpactRiskAcceptance.Low = true
		report := new(artifacts.SemgrepReportMin)

		report.Results = []artifacts.SemgrepResults{
			{Extra: artifacts.SemgrepExtra{Severity: "error", Metadata: artifacts.SemgrepMetadata{Impact: "low"}}},
			{Extra: artifacts.SemgrepExtra{Severity: "error", Metadata: artifacts.SemgrepMetadata{Impact: "low"}}},
			{Extra: artifacts.SemgrepExtra{Severity: "error", Metadata: artifacts.SemgrepMetadata{Impact: "low"}}},
			{Extra: artifacts.SemgrepExtra{Severity: "error", Metadata: artifacts.SemgrepMetadata{Impact: "low"}}},
			{Extra: artifacts.SemgrepExtra{Severity: "error", Metadata: artifacts.SemgrepMetadata{Impact: "medium"}}},
		}

		want := false
		got := true

		err := validateSemgrepRules(config, report)
		if err != nil {
			got = false
		}

		if want != got {
			t.Fatalf("want: %t got: %t", want, got)
		}

	})
}

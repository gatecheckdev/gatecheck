package artifacts

import (
	"encoding/json"
	"testing"
)

func TestSarifFindings(t *testing.T) {
	report := &SarifReport{}
	if err := json.Unmarshal(mustRead(t, "../../test/sarif-kics.json"), report); err != nil {
		t.Fatal(err)
	}
	findings, err := report.Findings()
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3 (pass and suppressed omitted)", len(findings))
	}
	if findings[0].Severity != "critical" || findings[0].RuleID != "611ab018" || findings[0].Location() != "main.tf:12" {
		t.Fatalf("first finding: %+v", findings[0])
	}
	if findings[1].Severity != "medium" || findings[1].RuleID != "4a8c5d22" {
		t.Fatalf("security-severity on the rule should win: %+v", findings[1])
	}
	if findings[2].Severity != "low" || findings[2].Tool != "KICS" {
		t.Fatalf("note level should be low: %+v", findings[2])
	}
}

func TestSarifLevelAndVersion(t *testing.T) {
	semgrep := &SarifReport{}
	if err := json.Unmarshal(mustRead(t, "../../test/sarif-semgrep.json"), semgrep); err != nil {
		t.Fatal(err)
	}
	findings, err := semgrep.Findings()
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].Severity != "high" || findings[1].Severity != "medium" {
		t.Fatalf("%+v", findings)
	}

	bandit := &SarifReport{}
	if err := json.Unmarshal(mustRead(t, "../../test/sarif-bandit.json"), bandit); err != nil {
		t.Fatal(err)
	}
	findings, err = bandit.Findings()
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].Severity != "high" || findings[1].Severity != "low" {
		t.Fatalf("bandit: %+v", findings)
	}

	old := &SarifReport{Version: "2.0.0", Runs: []SarifRun{}}
	if _, err := old.Findings(); err == nil {
		t.Fatal("expected unsupported version")
	}
}

func TestSecuritySeverityRanges(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{9, "critical"},
		{8.9, "high"},
		{7, "high"},
		{4, "medium"},
		{0.1, "low"},
		{0, "none"},
	}
	for _, tc := range cases {
		if got := severityFromSecurityScore(tc.score); got != tc.want {
			t.Fatalf("score %v got %s want %s", tc.score, got, tc.want)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	body, err := osRead(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

package gatecheck

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
)

const (
	scorecardReport  = "../../test/scorecard-report.json"
	trufflehogReport = "../../test/trufflehog-report.json"
)

func TestDetectScorecardAndTrufflehog(t *testing.T) {
	for file, want := range map[string]artifacts.ReportKind{
		scorecardReport:  artifacts.KindScorecard,
		trufflehogReport: artifacts.KindTrufflehog,
	} {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if got := artifacts.Detect(content); got != want {
			t.Fatalf("%s detected as %q", file, got)
		}
		firstLine, _, _ := bytes.Cut(content, []byte("\n"))
		if want == artifacts.KindTrufflehog && artifacts.Detect(firstLine) != want {
			t.Fatal("a single trufflehog line should be detected")
		}
	}
	if got := resolveKind(nil, "trufflehog-report.json", false); got != artifacts.KindTrufflehog {
		t.Fatalf("empty trufflehog output by name: %q", got)
	}
}

func TestValidateScorecard(t *testing.T) {
	if err := validateFile(t, NewDefaultConfig(), scorecardReport); err != nil {
		t.Fatalf("rules off: %v", err)
	}
	config := NewDefaultConfig()
	config.Scorecard.Enabled = true
	config.Scorecard.MinScore = 6
	if err := validateFile(t, config, scorecardReport); err != nil {
		t.Fatalf("aggregate 6.2 over 6: %v", err)
	}
	config.Scorecard.MinScore = 7
	err := validateFile(t, config, scorecardReport)
	if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("aggregate under 7: %v", err)
	}

	config.Scorecard.MinScore = 0
	config.Scorecard.Checks = []configScorecardCheck{
		{Name: "dangerous-workflow", MinScore: 10},
		{Name: "Signed-Releases", MinScore: 8},
		{Name: "Not-A-Check", MinScore: 5},
	}
	if err := validateFile(t, config, scorecardReport); err != nil {
		t.Fatalf("passing, inconclusive, and missing checks should pass: %v", err)
	}
	config.Scorecard.Checks = append(config.Scorecard.Checks, configScorecardCheck{Name: "Token-Permissions", MinScore: 1})
	err = validateFile(t, config, scorecardReport)
	if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "Token-Permissions") {
		t.Fatalf("token permissions: %v", err)
	}
}

func TestValidateTrufflehog(t *testing.T) {
	if err := validateFile(t, NewDefaultConfig(), trufflehogReport); err != nil {
		t.Fatalf("rules off: %v", err)
	}
	config := NewDefaultConfig()
	config.Trufflehog.LimitEnabled = true
	if err := validateFile(t, config, trufflehogReport); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("any secret: %v", err)
	}
	unverified := []byte(strings.Split(string(mustRead(t, trufflehogReport)), "\n")[0])
	config.Trufflehog.VerifiedOnly = true
	if err := Validate(config, bytes.NewReader(unverified), "scan.json"); err != nil {
		t.Fatalf("unverified only, verifiedOnly set: %v", err)
	}
	if err := validateFile(t, config, trufflehogReport); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("verified secret: %v", err)
	}
	if err := Validate(config, bytes.NewReader(nil), "trufflehog-report.json"); err != nil {
		t.Fatalf("empty trufflehog output: %v", err)
	}
	var out bytes.Buffer
	if err := List(&out, bytes.NewReader(nil), "trufflehog-report.json"); err != nil || !strings.Contains(out.String(), "No trufflehog findings") {
		t.Fatalf("empty list: %v %q", err, out.String())
	}
	if strings.Contains(string(mustRead(t, trufflehogReport)), "hunter2") {
		t.Fatal("fixture leaks a secret value")
	}
}

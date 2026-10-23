package artifacts

import (
	"encoding/json"
	"os"
	"testing"
)

func osRead(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func TestCyclonedxHighestSeverity(t *testing.T) {
	score := func(n float64) cyclonedxScore {
		return cyclonedxScore{Value: n, Valid: true}
	}
	cases := []struct {
		name string
		vuln CyclonedxVulnerability
		want string
	}{
		{
			name: "empty ratings",
			vuln: CyclonedxVulnerability{},
			want: "unknown",
		},
		{
			name: "critical word",
			vuln: CyclonedxVulnerability{Ratings: []CyclonedxRating{{Severity: "critical"}}},
			want: "critical",
		},
		{
			name: "capitalized",
			vuln: CyclonedxVulnerability{Ratings: []CyclonedxRating{{Severity: "HIGH"}}},
			want: "high",
		},
		{
			name: "highest of several",
			vuln: CyclonedxVulnerability{Ratings: []CyclonedxRating{{Severity: "low"}, {Severity: "medium"}, {Severity: "info"}}},
			want: "medium",
		},
		{
			name: "score only v3",
			vuln: CyclonedxVulnerability{Ratings: []CyclonedxRating{{Score: score(9.8), Method: "CVSSv31"}}},
			want: "critical",
		},
		{
			name: "score only v2",
			vuln: CyclonedxVulnerability{Ratings: []CyclonedxRating{{Score: score(9), Method: "CVSSv2"}}},
			want: "high",
		},
		{
			name: "explicit word beats score",
			vuln: CyclonedxVulnerability{Ratings: []CyclonedxRating{{Severity: "low", Score: score(9.8), Method: "CVSSv31"}}},
			want: "low",
		},
		{
			name: "top level severity",
			vuln: CyclonedxVulnerability{Severity: "Medium"},
			want: "medium",
		},
		{
			name: "important alias",
			vuln: CyclonedxVulnerability{Ratings: []CyclonedxRating{{Severity: "important"}}},
			want: "high",
		},
		{
			name: "negligible",
			vuln: CyclonedxVulnerability{Ratings: []CyclonedxRating{{Severity: "negligible"}}},
			want: "none",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.vuln.HighestSeverity(); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestCyclonedxIdentityAndPackages(t *testing.T) {
	report := CyclonedxReportMin{
		Components: []CyclonedxComponent{{BOMRef: "pkg:npm/left-pad@1.3.0", Name: "left-pad", Version: "1.3.0"}},
		Vulnerabilities: []CyclonedxVulnerability{
			{ID: "CVE-1", Affects: []CyclondexAffectedPackage{{Ref: "pkg:npm/left-pad@1.3.0"}}},
			{BOMRef: "vuln-without-id", Affects: []CyclondexAffectedPackage{{Ref: "missing"}}},
		},
	}
	if report.Vulnerabilities[0].Identity() != "CVE-1" {
		t.Fatal(report.Vulnerabilities[0].Identity())
	}
	if report.Vulnerabilities[1].Identity() != "vuln-without-id" {
		t.Fatal(report.Vulnerabilities[1].Identity())
	}
	if got := report.AffectedPackages(0); got != "left-pad [1.3.0]" {
		t.Fatal(got)
	}
	if got := report.AffectedPackages(1); got != "missing" {
		t.Fatal(got)
	}
}

func TestCyclonedxStringScore(t *testing.T) {
	var report CyclonedxReportMin
	src := []byte(`{"vulnerabilities":[{"id":"CVE-1","ratings":[{"score":"9.8","method":"CVSSv31"}]}]}`)
	if err := json.Unmarshal(src, &report); err != nil {
		t.Fatal(err)
	}
	if got := report.Vulnerabilities[0].HighestSeverity(); got != "critical" {
		t.Fatalf("got %q", got)
	}
}

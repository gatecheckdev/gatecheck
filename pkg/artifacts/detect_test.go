package artifacts

import (
	"os"
	"testing"
)

func TestDetect(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want ReportKind
	}{
		{name: "empty", src: "", want: KindUnknown},
		{name: "ambiguous object", src: `{}`, want: KindUnknown},
		{name: "ambiguous grype matches", src: `{"matches":[]}`, want: KindUnknown},
		{name: "ambiguous semgrep results", src: `{"results":[]}`, want: KindUnknown},
		{name: "empty gitleaks", src: `[]`, want: KindUnknown},
		{
			name: "grype descriptor",
			src:  `{"descriptor":{"name":"grype","version":"0.121.0"},"matches":[]}`,
			want: KindGrype,
		},
		{
			name: "grype matches",
			src:  `{"matches":[{"vulnerability":{"id":"CVE-1","severity":"High"},"artifact":{"name":"pkg","version":"1"}}]}`,
			want: KindGrype,
		},
		{
			name: "cyclonedx bom",
			src:  `{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[]}`,
			want: KindCycloneDX,
		},
		{
			name: "cyclonedx case",
			src:  `{"bomFormat":"cyclonedx","specVersion":"1.6"}`,
			want: KindCycloneDX,
		},
		{
			name: "cyclonedx written by grype",
			src:  `{"bomFormat":"CycloneDX","metadata":{"tools":[{"name":"grype"}]},"vulnerabilities":[{"id":"CVE-1","ratings":[{"severity":"critical"}]}]}`,
			want: KindCycloneDX,
		},
		{
			name: "sarif",
			src:  `{"version":"2.1.0","runs":[]}`,
			want: KindSARIF,
		},
		{
			name: "sarif schema null runs",
			src:  `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":null}`,
			want: KindSARIF,
		},
		{
			name: "sarif 2.0",
			src:  `{"version":"2.0.0","runs":[]}`,
			want: KindUnknown,
		},
		{
			name: "syft descriptor",
			src:  `{"descriptor":{"name":"syft"},"artifacts":[]}`,
			want: KindSyft,
		},
		{
			name: "syft schema",
			src:  `{"artifacts":[],"schema":{"url":"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.0.json"}}`,
			want: KindSyft,
		},
		{
			name: "semgrep",
			src:  `{"version":"1.182.1","results":[{"check_id":"x","extra":{"severity":"ERROR"}}],"errors":[]}`,
			want: KindSemgrep,
		},
		{
			name: "semgrep empty results",
			src:  `{"results":[],"errors":[]}`,
			want: KindSemgrep,
		},
		{
			name: "gitleaks",
			src:  `[{"RuleID":"jwt","File":"a.ts","Commit":"abcdef0123456789","StartLine":1}]`,
			want: KindGitleaks,
		},
		{
			name: "lcov",
			src:  "SF:main.go\nDA:1,1\nLF:1\nLH:1\nend_of_record\n",
			want: KindLCOV,
		},
		{
			name: "clover",
			src:  `<?xml version="1.0"?><coverage clover="4.2.0" generated="1"></coverage>`,
			want: KindClover,
		},
		{
			name: "cobertura",
			src:  `<?xml version="1.0"?><coverage line-rate="0.8" branch-rate="0.5"></coverage>`,
			want: KindCobertura,
		},
		{
			name: "gzip is not sniffed as text",
			src:  string([]byte{0x1f, 0x8b, 0x08, 'S', 'F', ':', '\n', 'D', 'A', ':'}),
			want: KindUnknown,
		},
		{
			name: "trivy schema and type",
			src:  `{"SchemaVersion":2,"ArtifactType":"filesystem","Results":[]}`,
			want: KindTrivy,
		},
		{
			name: "trivy results only",
			src:  `{"SchemaVersion":2,"Results":[{"Target":"alpine","Class":"os-pkgs"}]}`,
			want: KindTrivy,
		},
		{
			name: "schema version alone is ambiguous",
			src:  `{"SchemaVersion":2}`,
			want: KindUnknown,
		},
		{
			name: "osv packages",
			src:  `{"results":[{"source":{"path":"go.mod","type":"lockfile"},"packages":[]}]}`,
			want: KindOSV,
		},
		{
			name: "empty results stay ambiguous",
			src:  `{"results":[]}`,
			want: KindUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect([]byte(tc.src))
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestDetectFixtures(t *testing.T) {
	cases := []struct {
		file string
		want ReportKind
	}{
		{file: "../../test/grype-report.json", want: KindGrype},
		{file: "../../test/cyclonedx-grype-sbom.json", want: KindCycloneDX},
		{file: "../../test/cyclonedx-syft-sbom.json", want: KindCycloneDX},
		{file: "../../test/cyclonedx-trivy-sbom.json", want: KindCycloneDX},
		{file: "../../test/cyclonedx-mixed.json", want: KindCycloneDX},
		{file: "../../test/semgrep-sast-report.json", want: KindSemgrep},
		{file: "../../test/semgrep-osemgrep-report.json", want: KindSemgrep},
		{file: "../../test/gitleaks-report.json", want: KindGitleaks},
		{file: "../../test/sarif-kics.json", want: KindSARIF},
		{file: "../../test/sarif-semgrep.json", want: KindSARIF},
		{file: "../../test/sarif-checkov.json", want: KindSARIF},
		{file: "../../test/sarif-govulncheck.json", want: KindSARIF},
		{file: "../../test/sarif-bandit.json", want: KindSARIF},
		{file: "../../test/trivy-report.json", want: KindTrivy},
		{file: "../../test/osv-scanner-report.json", want: KindOSV},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			body, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatal(err)
			}
			got := Detect(body)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

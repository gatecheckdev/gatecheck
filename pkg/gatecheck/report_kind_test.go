package gatecheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
)

func TestKindFallsBackToFilename(t *testing.T) {
	if got := KindForList([]byte(`{"matches":[]}`), "grype.json"); got != artifacts.KindGrype {
		t.Fatalf("got %s", got)
	}
	if got := KindForList([]byte(`{"results":[]}`), "semgrep.json"); got != artifacts.KindSemgrep {
		t.Fatalf("got %s", got)
	}
	if got := KindForList([]byte(`[]`), "gitleaks.json"); got != artifacts.KindGitleaks {
		t.Fatalf("got %s", got)
	}
	if got := KindForList([]byte(`not a report`), "scan.json"); got != artifacts.KindUnknown {
		t.Fatalf("got %s", got)
	}
	if got := resolveKind([]byte(`not a report`), "gatecheck-reports.tar.gz", false); got != artifacts.KindUnknown {
		t.Fatalf("validate filename fallback should ignore gatecheck without bundle: %s", got)
	}
	if got := KindForList([]byte(`not a report`), "gatecheck-reports.tar.gz"); got != artifacts.KindBundle {
		t.Fatalf("list filename fallback should accept gatecheck: %s", got)
	}
}

func TestContentWinsOverFilename(t *testing.T) {
	cdx := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[{"id":"CVE-2024-1111","ratings":[{"severity":"critical"}]}]}`)
	got := renderList(t, "cyclonedx-grype-sbom.json", cdx, nil)
	if !strings.Contains(got, "No cyclonedx vulnerabilities") && !strings.Contains(got, "CVE-2024-1111") {
		t.Fatalf("%s", got)
	}
	if strings.Contains(got, "No grype") || strings.Contains(got, "GRYPE SEVERITY") {
		t.Fatalf("listed as grype:\n%s", got)
	}

	config := NewDefaultConfig()
	config.Grype.SeverityLimit.Critical.Enabled = true
	config.Cyclonedx.SeverityLimit.Critical.Enabled = true
	config.Cyclonedx.SeverityLimit.Critical.Limit = 0
	err := Validate(config, bytes.NewReader(cdx), "cyclonedx-grype-sbom.json")
	if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "CycloneDx") {
		t.Fatalf("got %v", err)
	}
}

func TestCycloneDXProducersListTheSameWay(t *testing.T) {
	mixed := mustRead(t, "../../test/cyclonedx-mixed.json")
	for _, filename := range []string{"cyclonedx-mixed.json", "grype-report.json", "trivy.json", "dependency-track.json"} {
		t.Run(filename, func(t *testing.T) {
			got := renderList(t, filename, mixed, nil)
			for _, needle := range []string{"CYCLONEDX CVE ID", "CVE-2024-0001", "critical", "left-pad [1.3.0]", "requests [2.28.0]", "vuln-without-id", "missing-component"} {
				if !strings.Contains(got, needle) {
					t.Fatalf("missing %q\n%s", needle, got)
				}
			}
			if strings.Contains(got, "No grype") {
				t.Fatal(got)
			}
		})
	}

	config := NewDefaultConfig()
	config.Cyclonedx.SeverityLimit.Critical.Enabled = true
	config.Cyclonedx.SeverityLimit.Critical.Limit = 0
	err := Validate(config, bytes.NewReader(mixed), "scan.json")
	if !errors.Is(err, ErrValidationFailure) {
		t.Fatal(err)
	}

	config = NewDefaultConfig()
	config.Cyclonedx.SeverityLimit.Critical.Enabled = true
	config.Cyclonedx.CVERiskAcceptance.Enabled = true
	config.Cyclonedx.CVERiskAcceptance.CVEs = []configCVE{{ID: "cve-2024-0001"}}
	config.Cyclonedx.SeverityLimit.High.Enabled = true
	config.Cyclonedx.SeverityLimit.High.Limit = 0
	err = Validate(config, bytes.NewReader(mixed), "scan.json")
	if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "Severity") {
		t.Fatalf("high findings should still fail after the critical is allowed: %v", err)
	}
}

func TestRepoCycloneDXReports(t *testing.T) {
	grype := mustRead(t, "../../test/cyclonedx-grype-sbom.json")
	got := renderList(t, "cyclonedx-grype-sbom.json", grype, nil)
	if strings.Contains(got, "No grype") || strings.Contains(got, "GRYPE SEVERITY") {
		t.Fatal("grype cyclonedx bom was listed as grype")
	}
	if !strings.Contains(got, "CVE-2016-2781") || !strings.Contains(got, "CYCLONEDX CVE ID") {
		t.Fatalf("missing cyclonedx row:\n%.400s", got)
	}
	config := NewDefaultConfig()
	config.Cyclonedx.SeverityLimit.Low.Enabled = true
	config.Cyclonedx.SeverityLimit.Low.Limit = 0
	if err := Validate(config, bytes.NewReader(grype), "cyclonedx-grype-sbom.json"); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("low limit: %v", err)
	}

	trivy := mustRead(t, "../../test/cyclonedx-trivy-sbom.json")
	got = renderList(t, "trivy-report.json", trivy, nil)
	if !strings.Contains(got, "CVE-2023-29383") || !strings.Contains(got, "CYCLONEDX CVE ID") {
		t.Fatalf("trivy bom was not listed as cyclonedx:\n%.400s", got)
	}
	config = NewDefaultConfig()
	config.Cyclonedx.SeverityLimit.High.Enabled = true
	if err := Validate(config, bytes.NewReader(trivy), "trivy-report.json"); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("trivy high limit: %v", err)
	}

	syft := mustRead(t, "../../test/cyclonedx-syft-sbom.json")
	got = renderList(t, "image.syft.json", syft, nil)
	if got != "No cyclonedx vulnerabilities\n" {
		t.Fatalf("syft cyclonedx bom: %q", got)
	}
	if err := Validate(NewDefaultConfig(), bytes.NewReader(syft), "image.syft.json"); err != nil {
		t.Fatal(err)
	}
}

func TestSarifListAndValidate(t *testing.T) {
	kics := mustRead(t, "../../test/sarif-kics.json")
	assertGolden(t, "notes.json", kics, nil, "testdata/sarif-kics.golden")

	for _, file := range []string{
		"../../test/sarif-semgrep.json",
		"../../test/sarif-checkov.json",
		"../../test/sarif-govulncheck.json",
		"../../test/sarif-bandit.json",
	} {
		t.Run(file, func(t *testing.T) {
			body := mustRead(t, file)
			got := renderList(t, "scan.json", body, nil)
			if !strings.Contains(got, "SARIF RULE ID") {
				t.Fatalf("%s", got)
			}
			if err := Validate(NewDefaultConfig(), bytes.NewReader(body), "scan.json"); err != nil {
				t.Fatal(err)
			}
		})
	}

	semgrep := mustRead(t, "../../test/sarif-semgrep.json")
	if strings.Contains(renderList(t, "semgrep.sarif", semgrep, nil), "SEMGREP CHECK ID") {
		t.Fatal("semgrep sarif was listed as semgrep json")
	}

	config := NewDefaultConfig()
	config.Sarif.SeverityLimit.Critical.Enabled = true
	config.Sarif.SeverityLimit.Critical.Limit = 0
	err := Validate(config, bytes.NewReader(kics), "kics.sarif")
	if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "SARIF") {
		t.Fatalf("%v", err)
	}

	config = NewDefaultConfig()
	config.Sarif.RuleLimit.Enabled = true
	config.Sarif.RuleLimit.Rules = []configRule{{ID: "b602"}}
	bandit := mustRead(t, "../../test/sarif-bandit.json")
	err = Validate(config, bytes.NewReader(bandit), "bandit.json")
	if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("%v", err)
	}

	config = NewDefaultConfig()
	config.Sarif.SeverityLimit.High.Enabled = true
	config.Sarif.SeverityLimit.High.Limit = 0
	config.Sarif.RuleRiskAcceptance.Enabled = true
	config.Sarif.RuleRiskAcceptance.Rules = []configRule{{ID: "B602"}}
	if err := Validate(config, bytes.NewReader(bandit), "bandit.json"); err != nil {
		t.Fatal(err)
	}

	// A denied rule fails even when that severity limit is disabled.
	config = NewDefaultConfig()
	config.Sarif.RuleLimit.Enabled = true
	config.Sarif.RuleLimit.Rules = []configRule{{ID: "B101"}}
	err = Validate(config, bytes.NewReader(bandit), "bandit.json")
	if !errors.Is(err, ErrValidationFailure) {
		t.Fatal(err)
	}

	old := []byte(`{"version":"2.0.0","runs":[]}`)
	if err := Validate(NewDefaultConfig(), bytes.NewReader(old), "out.sarif"); err == nil {
		t.Fatal("expected sarif 2.0 to fail")
	}
}

func TestBundleUsesStoredContent(t *testing.T) {
	kics := mustRead(t, "../../test/sarif-kics.json")
	cdx := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[{"id":"CVE-9","ratings":[{"severity":"high"}]}]}`)
	bundle := archive.NewBundle()
	bundle.Add(kics, "notes.json", []string{"ci"})
	bundle.Add(cdx, "grype.json", nil)
	var buf bytes.Buffer
	if _, err := archive.TarGzipBundle(&buf, bundle); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), buf.Bytes()...)

	listed := renderList(t, "scan.tar.gz", raw, nil)
	if !strings.Contains(listed, "notes.json") || !strings.Contains(listed, "grype.json") {
		t.Fatalf("%s", listed)
	}

	config := NewDefaultConfig()
	config.Sarif.SeverityLimit.Critical.Enabled = true
	config.Sarif.SeverityLimit.Critical.Limit = 0
	config.Cyclonedx.SeverityLimit.High.Enabled = true
	config.Cyclonedx.SeverityLimit.High.Limit = 0
	err := Validate(config, bytes.NewReader(raw), "scan.tar.gz")
	if !errors.Is(err, ErrValidationFailure) {
		t.Fatal(err)
	}
	if !strings.Contains(err.Error(), "SARIF") || !strings.Contains(err.Error(), "CycloneDx") {
		t.Fatalf("%v", err)
	}
}

func TestListAllAction(t *testing.T) {
	supported, epss := ListAllAction([]byte(`{"bomFormat":"CycloneDX"}`), "scan.json")
	if !supported || !epss {
		t.Fatalf("supported %v epss %v", supported, epss)
	}
	supported, epss = ListAllAction([]byte("SF:main.go\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"), "out.txt")
	if supported || epss {
		t.Fatal("coverage should stay out of list-all")
	}
	lcov := []byte("SF:main.go\nDA:1,1\nLF:1\nLH:1\nend_of_record\n")
	got := renderList(t, "out.txt", lcov, nil)
	if !strings.Contains(got, "LINES COVERED") {
		t.Fatalf("%s", got)
	}
}

func TestGatecheckBundleMagic(t *testing.T) {
	bundle := archive.NewBundle()
	bundle.Add([]byte(`{"matches":[]}`), "grype.json", nil)
	var buf bytes.Buffer
	if _, err := archive.TarGzipBundle(&buf, bundle); err != nil {
		t.Fatal(err)
	}
	if !isGatecheckBundle(buf.Bytes()) {
		t.Fatal("expected bundle")
	}
	plain := gzipBytes(t, []byte("hello"))
	if isGatecheckBundle(plain) {
		t.Fatal("plain gzip is not a bundle")
	}
}

func gzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "a.txt", Size: int64(len(payload)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSyftJSONStillErrors(t *testing.T) {
	src := []byte(`{"descriptor":{"name":"syft"},"artifacts":[]}`)
	if err := List(&bytes.Buffer{}, bytes.NewReader(src), "scan.json"); err == nil || !strings.Contains(err.Error(), "syft") {
		t.Fatal(err)
	}
	if err := Validate(NewDefaultConfig(), bytes.NewReader(src), "bom.syft.json"); err == nil || !strings.Contains(err.Error(), "syft") {
		t.Fatal(err)
	}
}

func TestPartialConfigIgnoresMissingSarif(t *testing.T) {
	raw := []byte("version: \"1\"\ngrype:\n  severityLimit:\n    critical:\n      enabled: true\n      limit: 0\n")
	path := t.TempDir() + "/gatecheck.yaml"
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	config := &Config{}
	if err := NewConfigDecoder(path).Decode(config); err != nil {
		t.Fatal(err)
	}
	if config.Sarif.SeverityLimit.Critical.Enabled || config.Sarif.RuleLimit.Enabled {
		t.Fatal("missing sarif section should stay disabled")
	}
	if !config.Grype.SeverityLimit.Critical.Enabled {
		t.Fatal("existing grype config was not decoded")
	}
}

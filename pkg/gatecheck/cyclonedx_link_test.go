package gatecheck

import (
	"strings"
	"testing"
)

func TestCyclonedxLinkIsPerVulnerability(t *testing.T) {
	src := []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [{"bom-ref": "pkg-a", "name": "a", "version": "1.0.0"}],
  "vulnerabilities": [
    {"id": "CVE-2024-0001", "ratings": [{"severity": "critical"}], "advisories": [{"url": "https://example.com/advisory-1"}], "affects": [{"ref": "pkg-a"}]},
    {"id": "CVE-2024-0002", "ratings": [{"severity": "high"}], "source": {"name": "NVD", "url": "https://example.com/source-2"}, "affects": [{"ref": "pkg-a"}]},
    {"id": "CVE-2024-0003", "ratings": [{"severity": "medium"}], "references": [{"id": "GHSA-xxxx", "source": {"url": "https://example.com/ref-3"}}], "affects": [{"ref": "pkg-a"}]},
    {"id": "CVE-2024-0004", "ratings": [{"severity": "low"}], "affects": [{"ref": "pkg-a"}]}
  ]
}`)
	got := renderList(t, "bom.json", src, nil)
	want := map[string]string{
		"CVE-2024-0001": "https://example.com/advisory-1",
		"CVE-2024-0002": "https://example.com/source-2",
		"CVE-2024-0003": "https://example.com/ref-3",
		"CVE-2024-0004": "-",
	}
	for id, link := range want {
		line := lineWith(got, id)
		if line == "" {
			t.Fatalf("missing %s\n%s", id, got)
		}
		if !strings.Contains(line, link) {
			t.Fatalf("%s: want link %q, got line %q", id, link, line)
		}
		if link == "-" && strings.Contains(line, "https://") {
			t.Fatalf("%s: borrowed another row's link: %q", id, line)
		}
	}
}

func lineWith(text, needle string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}

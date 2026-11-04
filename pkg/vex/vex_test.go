package vex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const openVEXSample = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/1",
  "author": "ada",
  "timestamp": "2026-10-01T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2026-0001", "aliases": ["GHSA-aaaa-bbbb-cccc"]},
      "products": [
        {"@id": "pkg:oci/app@sha256:abc", "subcomponents": [{"@id": "pkg:golang/example.com/lib@v1.2.3"}]}
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    },
    {
      "vulnerability": {"name": "CVE-2026-0002"},
      "products": [{"@id": "pkg:oci/app"}],
      "status": "fixed"
    },
    {
      "vulnerability": {"name": "CVE-2026-0003"},
      "products": [{"@id": "pkg:oci/app"}],
      "status": "under_investigation"
    },
    {
      "vulnerability": {"name": "CVE-2026-0004"},
      "products": [{"@id": "pkg:oci/app"}],
      "status": "not_affected",
      "justification": "component_not_present",
      "timestamp": "2026-10-01T00:00:00Z"
    },
    {
      "vulnerability": {"name": "CVE-2026-0004"},
      "products": [{"@id": "pkg:oci/app"}],
      "status": "affected",
      "action_statement": "upgrade",
      "timestamp": "2026-10-05T00:00:00Z"
    }
  ]
}`

const openVEXLegacy = `{
  "@context": "https://openvex.dev/ns",
  "statements": [
    {"vulnerability": "CVE-2026-0009", "products": ["pkg:npm/left-pad@1.0.0"], "subcomponents": ["pkg:npm/left-pad@1.0.0"], "status": "not_affected"}
  ]
}`

const cdxVEX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [{"bom-ref": "lib-1", "name": "lib", "purl": "pkg:pypi/requests@2.31.0"}],
  "vulnerabilities": [
    {"id": "CVE-2026-0100", "analysis": {"state": "not_affected", "justification": "code_not_reachable"}, "affects": [{"ref": "lib-1"}]},
    {"id": "CVE-2026-0101", "analysis": {"state": "false_positive"}, "affects": [{"ref": "pkg:pypi/urllib3@2.0.0"}]},
    {"id": "CVE-2026-0102", "analysis": {"state": "exploitable"}},
    {"id": "CVE-2026-0103", "analysis": {"state": "resolved"}},
    {"id": "CVE-2026-0104"}
  ]
}`

func decode(t *testing.T, body string) *Document {
	t.Helper()
	doc, err := Decode(strings.NewReader(body), "test.json")
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestOpenVEX(t *testing.T) {
	doc := decode(t, openVEXSample)
	cases := []struct {
		name string
		f    Finding
		want bool
	}{
		{"subcomponent match", Finding{IDs: []string{"CVE-2026-0001"}, PURL: "pkg:golang/example.com/lib@v1.2.3"}, true},
		{"alias match", Finding{IDs: []string{"GHSA-AAAA-BBBB-CCCC"}, PURL: "pkg:golang/example.com/lib@v1.2.3"}, true},
		{"other package", Finding{IDs: []string{"CVE-2026-0001"}, PURL: "pkg:golang/example.com/other@v1.2.3"}, false},
		{"other version", Finding{IDs: []string{"CVE-2026-0001"}, PURL: "pkg:golang/example.com/lib@v1.2.4"}, false},
		{"no purl on finding", Finding{IDs: []string{"CVE-2026-0001"}}, true},
		{"fixed, product only", Finding{IDs: []string{"cve-2026-0002"}, PURL: "pkg:deb/debian/openssl@3"}, true},
		{"under investigation", Finding{IDs: []string{"CVE-2026-0003"}}, false},
		{"later affected wins", Finding{IDs: []string{"CVE-2026-0004"}}, false},
		{"unknown id", Finding{IDs: []string{"CVE-1999-0001"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := doc.Suppressed(tc.f)
			if got != tc.want {
				t.Fatalf("suppressed=%v want %v", got, tc.want)
			}
		})
	}
	s, _ := doc.Suppressed(Finding{IDs: []string{"CVE-2026-0001"}})
	if s.Justification != "vulnerable_code_not_in_execute_path" || s.Source != "test.json" {
		t.Fatalf("statement %+v", s)
	}
}

func TestOpenVEXLegacyStrings(t *testing.T) {
	doc := decode(t, openVEXLegacy)
	if _, ok := doc.Suppressed(Finding{IDs: []string{"CVE-2026-0009"}, PURL: "pkg:npm/left-pad@1.0.0"}); !ok {
		t.Fatal("legacy statement should match")
	}
	if _, ok := doc.Suppressed(Finding{IDs: []string{"CVE-2026-0009"}, PURL: "pkg:npm/left-pad@2.0.0"}); ok {
		t.Fatal("other version should not match")
	}
}

func TestCycloneDXVEX(t *testing.T) {
	doc := decode(t, cdxVEX)
	if doc.Len() != 4 {
		t.Fatalf("statements %d", doc.Len())
	}
	cases := []struct {
		f    Finding
		want bool
	}{
		{Finding{IDs: []string{"CVE-2026-0100"}, PURL: "pkg:pypi/requests@2.31.0"}, true},
		{Finding{IDs: []string{"CVE-2026-0100"}, PURL: "pkg:pypi/flask@2.31.0"}, false},
		{Finding{IDs: []string{"CVE-2026-0101"}, PURL: "pkg:pypi/urllib3@2.0.0?arch=x"}, true},
		{Finding{IDs: []string{"CVE-2026-0102"}}, false},
		{Finding{IDs: []string{"CVE-2026-0103"}}, true},
		{Finding{IDs: []string{"CVE-2026-0104"}}, false},
	}
	for _, tc := range cases {
		if _, got := doc.Suppressed(tc.f); got != tc.want {
			t.Errorf("%v suppressed=%v want %v", tc.f, got, tc.want)
		}
	}
}

func TestLoadMergesFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.openvex.json")
	b := filepath.Join(dir, "b.cdx.json")
	if err := os.WriteFile(a, []byte(openVEXSample), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(cdxVEX), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := Load(a, "", b)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Len() != 9 {
		t.Fatalf("statements %d", doc.Len())
	}
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file should fail")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"matches": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), ErrUnknownFormat.Error()) {
		t.Fatalf("unknown format error %v", err)
	}
}

func TestPURLMatches(t *testing.T) {
	cases := []struct {
		want, got string
		ok        bool
	}{
		{"pkg:npm/%40scope/name@1.0.0", "pkg:npm/@scope/name@1.0.0", true},
		{"pkg:npm/@scope/name", "pkg:npm/@scope/name@9.9.9", true},
		{"PKG:NPM/name", "pkg:npm/name@1", true},
		{"pkg:npm/name@1", "pkg:npm/name@2", false},
		{"pkg:npm/name", "pkg:pypi/name", false},
		{"pkg:golang/a/b@v1#sub", "pkg:golang/a/b@v1?x=y", true},
		{"not-a-purl", "pkg:npm/name", false},
	}
	for _, tc := range cases {
		if got := PURLMatches(tc.want, tc.got); got != tc.ok {
			t.Errorf("PURLMatches(%q, %q) = %v", tc.want, tc.got, got)
		}
	}
}

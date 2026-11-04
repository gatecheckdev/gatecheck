package gatecheck

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigRoundTripEveryFormat(t *testing.T) {
	for _, format := range []string{"json", ".json", "yaml", "yml", ".yaml", "toml"} {
		t.Run(format, func(t *testing.T) {
			want := NewDefaultConfig()
			want.Grype.SeverityLimit.Critical = configLimit{Enabled: true, Limit: 2}
			want.License.Deny = []string{"GPL-*"}
			cve := configCVE{ID: "CVE-2026-1"}
			cve.Metadata.Tags = []string{"accepted"}
			want.Grype.CVERiskAcceptance.CVEs = []configCVE{cve}
			var buf bytes.Buffer
			if err := EncodeConfigTo(&buf, want, format); err != nil {
				t.Fatal(err)
			}
			canonical, _ := ConfigFormat(format)
			got := &Config{}
			if err := DecodeConfig(buf.Bytes(), canonical, got); err != nil {
				t.Fatalf("decode: %v\n%s", err, buf.String())
			}
			if got.String() != want.String() {
				t.Fatalf("round trip changed the config:\n%s", buf.String())
			}
			if canonical != "toml" && !strings.Contains(buf.String(), "\n  ") {
				t.Fatalf("%s output is not indented:\n%s", format, buf.String())
			}
		})
	}
	if _, err := ConfigFormat("xml"); err == nil {
		t.Fatal("xml should be rejected")
	}
}

func TestConfigUnknownKeys(t *testing.T) {
	cases := map[string]string{
		"gatecheck.yaml": "version: \"1\"\ngrype:\n  severityLimit:\n    critical:\n      enabled: true\n  severityLimt: {}\nbogus: 1\n",
		"gatecheck.json": `{"version":"1","grype":{"severityLimit":{"critical":{"enabled":true}}},"bogus":1}`,
		"gatecheck.toml": "version = \"1\"\nbogus = 1\n[grype.severityLimit.critical]\nenabled = true\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			config := NewDefaultConfig()
			err := NewConfigDecoder(file).Decode(config)
			if !errors.Is(err, ErrUnknownConfigKeys) || !strings.Contains(err.Error(), "bogus") {
				t.Fatalf("want unknown keys error naming bogus, got %v", err)
			}
			if !config.Grype.SeverityLimit.Critical.Enabled {
				t.Fatal("known keys should still be decoded")
			}
		})
	}
	clean := filepath.Join(t.TempDir(), "gatecheck.yml")
	if err := os.WriteFile(clean, []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewConfigDecoder(clean).Decode(NewDefaultConfig()); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "gatecheck.yaml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewConfigDecoder(empty).Decode(NewDefaultConfig()); err != nil {
		t.Fatalf("empty yaml: %v", err)
	}
}

func TestCoverageThresholdPercent(t *testing.T) {
	if got := coverageThreshold("line", 80); got != 0.8 {
		t.Fatalf("80 -> %v", got)
	}
	if got := coverageThreshold("line", 0.8); got != 0.8 {
		t.Fatalf("0.8 -> %v", got)
	}
	if got := coverageThreshold("line", 1); got != 1 {
		t.Fatalf("1 -> %v", got)
	}
}

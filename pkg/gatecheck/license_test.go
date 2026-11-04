package gatecheck

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
)

const (
	syftAlpine = "../../test/syft-alpine.json"
	cdxAlpine  = "../../test/cyclonedx-alpine-sbom.json"
)

func licenseConfig(mod func(*configLicense)) *Config {
	config := NewDefaultConfig()
	config.License.Enabled = true
	mod(&config.License)
	return config
}

func TestLicenseGateOnSBOMs(t *testing.T) {
	for _, report := range []string{syftAlpine, cdxAlpine} {
		t.Run(report, func(t *testing.T) {
			if err := validateFile(t, NewDefaultConfig(), report); err != nil {
				t.Fatalf("license rules off: %v", err)
			}

			denyGPL := licenseConfig(func(c *configLicense) { c.Deny = []string{"GPL-*"} })
			if err := validateFile(t, denyGPL, report); !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "License") {
				t.Fatalf("deny GPL: %v", err)
			}

			denyAGPL := licenseConfig(func(c *configLicense) { c.Deny = []string{"AGPL-*"} })
			if err := validateFile(t, denyAGPL, report); err != nil {
				t.Fatalf("deny AGPL: %v", err)
			}

			allowPermissive := licenseConfig(func(c *configLicense) {
				c.Allow = []string{"MIT", "Apache-2.0", "BSD-*", "Zlib", "MPL-2.0"}
			})
			if err := validateFile(t, allowPermissive, report); !errors.Is(err, ErrValidationFailure) {
				t.Fatalf("allow list without GPL: %v", err)
			}

			allowAll := licenseConfig(func(c *configLicense) {
				c.Allow = []string{"MIT", "Apache-2.0", "BSD-*", "Zlib", "MPL-2.0", "GPL-2.0-*"}
			})
			if err := validateFile(t, allowAll, report); err != nil {
				t.Fatalf("allow list with every license: %v", err)
			}

			accepted := licenseConfig(func(c *configLicense) {
				c.Deny = []string{"GPL-*"}
				for _, name := range []string{"alpine-baselayout", "alpine-baselayout-data", "apk-tools", "busybox", "busybox-binsh", "ssl_client", "scanelf", "musl-utils"} {
					c.PackageRiskAcceptance = append(c.PackageRiskAcceptance, configLicensePackage{Name: name})
				}
				c.PackageRiskAcceptance = append(c.PackageRiskAcceptance, configLicensePackage{PURL: "pkg:apk/alpine/libc-utils"})
			})
			if err := validateFile(t, accepted, report); err != nil {
				t.Fatalf("risk accepted packages: %v", err)
			}
		})
	}
}

func TestLicenseDenyUnknown(t *testing.T) {
	src := []byte(`{"descriptor":{"name":"syft"},"artifacts":[{"name":"mystery","version":"1.0","licenses":[]},{"name":"old","version":"2","licenses":["MIT"]}]}`)
	config := licenseConfig(func(c *configLicense) { c.DenyUnknown = true })
	if err := Validate(config, bytes.NewReader(src), "bom.syft.json"); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("unknown license should fail: %v", err)
	}
	config.License.PackageRiskAcceptance = []configLicensePackage{{Name: "MYSTERY"}}
	if err := Validate(config, bytes.NewReader(src), "bom.syft.json"); err != nil {
		t.Fatalf("accepted unknown: %v", err)
	}
}

func TestLicenseInBundleAndList(t *testing.T) {
	content, err := os.ReadFile(syftAlpine)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := List(&out, bytes.NewReader(content), "syft-alpine.json"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SYFT PACKAGE", "busybox", "GPL-2.0-only", "MPL-2.0 AND MIT"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("list output missing %q:\n%s", want, out.String())
		}
	}

	bundle := archive.NewBundle()
	if err := bundle.AddFrom(bytes.NewReader(content), "syft-alpine.json", nil); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := archive.TarGzipBundle(&buf, bundle); err != nil {
		t.Fatal(err)
	}
	denyGPL := licenseConfig(func(c *configLicense) { c.Deny = []string{"GPL-*"} })
	if err := Validate(denyGPL, bytes.NewReader(buf.Bytes()), "bundle.tar.gz"); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("bundle license gate: %v", err)
	}
}

func TestCyclonedxLicenseAndVulnErrorsJoin(t *testing.T) {
	config := licenseConfig(func(c *configLicense) { c.Deny = []string{"GPL-*"} })
	config.Cyclonedx.SeverityLimit.Low = configLimit{Enabled: true, Limit: 0}
	err := validateFile(t, config, "../../test/cyclonedx-grype-sbom.json")
	if !errors.Is(err, ErrValidationFailure) {
		t.Fatal(err)
	}
	if !strings.Contains(err.Error(), "License") || !strings.Contains(err.Error(), "Severity Limit") {
		t.Fatalf("want both failures, got %v", err)
	}
}

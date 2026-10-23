package update

import (
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	equal := [][2]string{
		{"0.8.1", "v0.8.1"},
		{"V0.8.1", "0.8.1"},
		{"0.8.1", "0.8.1+build.5"},
		{"v1.2.3-rc.1", "1.2.3-rc.1+meta"},
	}
	for _, pair := range equal {
		got, err := compareVersions(pair[0], pair[1])
		if err != nil {
			t.Fatalf("compare %s %s: %v", pair[0], pair[1], err)
		}
		if got != 0 {
			t.Fatalf("compare %s %s = %d, want 0", pair[0], pair[1], got)
		}
	}

	older := [][2]string{
		{"0.8.0", "0.8.1"},
		{"0.8.1", "0.9.0"},
		{"0.9.0", "1.0.0"},
		{"1.0.0-rc.1", "1.0.0"},
		{"1.0.0-alpha", "1.0.0-alpha.1"},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta"},
		{"1.0.0-alpha.beta", "1.0.0-beta"},
		{"1.0.0-beta", "1.0.0-beta.2"},
		{"1.0.0-beta.2", "1.0.0-beta.11"},
		{"1.0.0-beta.11", "1.0.0-rc.1"},
		{"1.0.0-1", "1.0.0-alpha"},
		{"1.2.3-rc.1", "1.2.3-rc.2"},
		{"1.2.3-rc.2", "1.2.3-rc.10"},
	}
	for _, pair := range older {
		got, err := compareVersions(pair[0], pair[1])
		if err != nil {
			t.Fatalf("compare %s %s: %v", pair[0], pair[1], err)
		}
		if got >= 0 {
			t.Fatalf("compare %s %s = %d, want < 0", pair[0], pair[1], got)
		}
		rev, err := compareVersions(pair[1], pair[0])
		if err != nil {
			t.Fatal(err)
		}
		if rev <= 0 {
			t.Fatalf("compare %s %s = %d, want > 0", pair[1], pair[0], rev)
		}
	}
}

func TestParseSemverRejects(t *testing.T) {
	for _, raw := range []string{
		"",
		"dev",
		"DEV",
		"[Not Provided]",
		"unknown",
		"1",
		"1.0",
		"01.0.0",
		"1.02.0",
		"1.0.0-01",
		"1.0.0-",
		"v",
		"1.0.0+",
		"1.0.0-rc.01",
	} {
		if _, err := parseSemver(raw); err == nil {
			t.Fatalf("parsed %q", raw)
		}
	}
}

func TestDisplayVersion(t *testing.T) {
	if got := displayVersion(" 0.8.1 "); got != "v0.8.1" {
		t.Fatalf("display %q", got)
	}
	if got := displayVersion(""); got != "dev" {
		t.Fatalf("display empty %q", got)
	}
	if got := displayVersion("dev"); got != "dev" {
		t.Fatalf("display dev %q", got)
	}
	if got := displayVersion("[Not Provided]"); got != "[Not Provided]" {
		t.Fatalf("display placeholder %q", got)
	}
}

func TestAssetNames(t *testing.T) {
	cases := []struct {
		version string
		goos    string
		goarch  string
		want    string
	}{
		{"v0.8.1", "linux", "amd64", "gatecheck_0.8.1_linux_amd64.tar.gz"},
		{"0.8.1", "linux", "arm64", "gatecheck_0.8.1_linux_arm64.tar.gz"},
		{"v0.8.1", "linux", "386", "gatecheck_0.8.1_linux_386.tar.gz"},
		{"v0.8.1", "darwin", "amd64", "gatecheck_0.8.1_darwin_amd64.tar.gz"},
		{"v0.8.1", "darwin", "arm64", "gatecheck_0.8.1_darwin_arm64.tar.gz"},
		{"v0.8.1", "windows", "amd64", "gatecheck_0.8.1_windows_amd64.tar.gz"},
		{"v0.8.1", "windows", "arm64", "gatecheck_0.8.1_windows_arm64.tar.gz"},
		{"v0.8.1", "windows", "386", "gatecheck_0.8.1_windows_386.tar.gz"},
		{"v1.2.3-rc.1", "linux", "amd64", "gatecheck_1.2.3-rc.1_linux_amd64.tar.gz"},
	}
	for _, tc := range cases {
		got, err := assetName(tc.version, tc.goos, tc.goarch)
		if err != nil {
			t.Fatalf("asset %s %s/%s: %v", tc.version, tc.goos, tc.goarch, err)
		}
		if got != tc.want {
			t.Fatalf("asset %s %s/%s = %s, want %s", tc.version, tc.goos, tc.goarch, got, tc.want)
		}
	}

	rejected := [][2]string{
		{"darwin", "386"},
		{"linux", "arm"},
		{"windows", "arm"},
		{"freebsd", "amd64"},
		{"linux", "ppc64le"},
	}
	for _, pair := range rejected {
		_, err := assetName("v0.8.1", pair[0], pair[1])
		if err == nil {
			t.Fatalf("accepted %s/%s", pair[0], pair[1])
		}
	}
}

func TestChecksumFor(t *testing.T) {
	const name = "gatecheck_0.8.1_linux_amd64.tar.gz"
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		label string
		body  string
		want  string
		bad   string
	}{
		{"two spaces", hash + "  " + name + "\n", hash, ""},
		{"one space", hash + " " + name + "\n", hash, ""},
		{"crlf", hash + "  " + name + "\r\n", hash, ""},
		{"prefix", "sha256:" + hash + "  " + name + "\n", hash, ""},
		{"upper", "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789  " + name, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", ""},
		{"star", hash + " *" + name + "\n", hash, ""},
		{"missing", hash + "  other.tar.gz\n", "", "missing"},
		{"invalid", "zz  " + name + "\n", "", "invalid"},
		{"comment ignored", "# " + hash + "  " + name + "\n" + hash + "  other\n", "", "missing"},
	}
	for _, tc := range cases {
		got, err := checksumFor([]byte(tc.body), name)
		if tc.bad != "" {
			if err == nil || !strings.Contains(err.Error(), tc.bad) {
				t.Fatalf("%s: got %q err %v", tc.label, got, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if got != tc.want {
			t.Fatalf("%s = %s, want %s", tc.label, got, tc.want)
		}
	}
}

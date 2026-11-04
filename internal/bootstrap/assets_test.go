package bootstrap

import (
	"fmt"
	"runtime"
	"testing"
)

func TestReleaseAssets(t *testing.T) {
	t.Parallel()
	grype, err := grypeAsset(GrypeVersion, Platform{GOOS: "linux", GOARCH: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if grype.Asset != fmt.Sprintf("grype_%s_linux_amd64.tar.gz", GrypeVersion) {
		t.Fatalf("grype asset %s", grype.Asset)
	}
	if grype.Checksum != fmt.Sprintf("grype_%s_checksums.txt", GrypeVersion) || grype.Binary != "grype" {
		t.Fatalf("grype checksum/binary %+v", grype)
	}

	syft, err := syftAsset(SyftVersion, Platform{GOOS: "windows", GOARCH: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if syft.Asset != fmt.Sprintf("syft_%s_windows_arm64.zip", SyftVersion) || syft.Binary != "syft.exe" {
		t.Fatalf("syft %+v", syft)
	}

	leaks, err := gitleaksAsset(GitleaksVersion, Platform{GOOS: "linux", GOARCH: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if leaks.Asset != fmt.Sprintf("gitleaks_%s_linux_x64.tar.gz", GitleaksVersion) {
		t.Fatalf("gitleaks linux %s", leaks.Asset)
	}
	mac, err := gitleaksAsset(GitleaksVersion, Platform{GOOS: "darwin", GOARCH: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if mac.Asset != fmt.Sprintf("gitleaks_%s_darwin_x64.tar.gz", GitleaksVersion) {
		t.Fatalf("gitleaks darwin %s", mac.Asset)
	}
	win, err := gitleaksAsset(GitleaksVersion, Platform{GOOS: "windows", GOARCH: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if win.Asset != fmt.Sprintf("gitleaks_%s_windows_x64.zip", GitleaksVersion) || win.Binary != "gitleaks.exe" {
		t.Fatalf("gitleaks windows %+v", win)
	}
	arm, err := gitleaksAsset(GitleaksVersion, Platform{GOOS: "linux", GOARCH: "arm", GOARM: "6"})
	if err != nil {
		t.Fatal(err)
	}
	if arm.Asset != fmt.Sprintf("gitleaks_%s_linux_armv6.tar.gz", GitleaksVersion) {
		t.Fatalf("gitleaks arm %s", arm.Asset)
	}

	if _, err := grypeAsset(GrypeVersion, Platform{GOOS: "windows", GOARCH: "arm64"}); err == nil {
		t.Fatal("grype windows/arm64 should fail")
	}
	if _, err := grypeAsset(GrypeVersion, Platform{GOOS: "linux", GOARCH: "riscv64"}); err == nil {
		t.Fatal("grype riscv64 should fail")
	}
	if _, err := gitleaksAsset(GitleaksVersion, Platform{GOOS: "darwin", GOARCH: "386"}); err == nil {
		t.Fatal("gitleaks darwin/386 should fail")
	}
	if _, err := gitleaksAsset(GitleaksVersion, Platform{GOOS: "linux", GOARCH: "arm", GOARM: "5"}); err == nil {
		t.Fatal("gitleaks armv5 should fail")
	}

	trivyCases := []struct {
		p    Platform
		want string
	}{
		{Platform{GOOS: "linux", GOARCH: "amd64"}, "Linux-64bit.tar.gz"},
		{Platform{GOOS: "linux", GOARCH: "386"}, "Linux-32bit.tar.gz"},
		{Platform{GOOS: "linux", GOARCH: "arm64"}, "Linux-ARM64.tar.gz"},
		{Platform{GOOS: "linux", GOARCH: "arm", GOARM: "7"}, "Linux-ARM.tar.gz"},
		{Platform{GOOS: "linux", GOARCH: "arm"}, "Linux-ARM.tar.gz"},
		{Platform{GOOS: "linux", GOARCH: "ppc64le"}, "Linux-PPC64LE.tar.gz"},
		{Platform{GOOS: "linux", GOARCH: "s390x"}, "Linux-s390x.tar.gz"},
		{Platform{GOOS: "darwin", GOARCH: "amd64"}, "macOS-64bit.tar.gz"},
		{Platform{GOOS: "darwin", GOARCH: "arm64"}, "macOS-ARM64.tar.gz"},
		{Platform{GOOS: "windows", GOARCH: "amd64"}, "windows-64bit.zip"},
		{Platform{GOOS: "freebsd", GOARCH: "amd64"}, "FreeBSD-64bit.tar.gz"},
	}
	for _, tc := range trivyCases {
		t.Run(tc.p.String(), func(t *testing.T) {
			t.Parallel()
			got, err := trivyAsset(TrivyVersion, tc.p)
			if err != nil {
				t.Fatal(err)
			}
			want := "trivy_" + TrivyVersion + "_" + tc.want
			if got.Asset != want {
				t.Fatalf("asset %s", got.Asset)
			}
			if got.Checksum != "trivy_"+TrivyVersion+"_checksums.txt" {
				t.Fatalf("checksum %s", got.Checksum)
			}
			binary := "trivy"
			if tc.p.GOOS == "windows" {
				binary = "trivy.exe"
			}
			if got.Binary != binary || got.DestName != binary {
				t.Fatalf("binary %+v", got)
			}
		})
	}
	if _, err := trivyAsset(TrivyVersion, Platform{GOOS: "windows", GOARCH: "arm64"}); err == nil {
		t.Fatal("trivy windows/arm64 should fail")
	}
	if _, err := trivyAsset(TrivyVersion, Platform{GOOS: "linux", GOARCH: "arm", GOARM: "6"}); err == nil {
		t.Fatal("trivy armv6 should fail")
	}
	if _, err := trivyAsset(TrivyVersion, Platform{GOOS: "darwin", GOARCH: "386"}); err == nil {
		t.Fatal("trivy darwin/386 should fail")
	}

	osvCases := []struct {
		p    Platform
		want string
	}{
		{Platform{GOOS: "linux", GOARCH: "amd64"}, "osv-scanner_linux_amd64"},
		{Platform{GOOS: "linux", GOARCH: "arm64"}, "osv-scanner_linux_arm64"},
		{Platform{GOOS: "darwin", GOARCH: "amd64"}, "osv-scanner_darwin_amd64"},
		{Platform{GOOS: "darwin", GOARCH: "arm64"}, "osv-scanner_darwin_arm64"},
		{Platform{GOOS: "windows", GOARCH: "amd64"}, "osv-scanner_windows_amd64.exe"},
		{Platform{GOOS: "windows", GOARCH: "arm64"}, "osv-scanner_windows_arm64.exe"},
	}
	for _, tc := range osvCases {
		t.Run(tc.p.String(), func(t *testing.T) {
			t.Parallel()
			got, err := osvScannerAsset(OSVScannerVersion, tc.p)
			if err != nil {
				t.Fatal(err)
			}
			if got.Asset != tc.want || !got.Raw {
				t.Fatalf("asset %+v", got)
			}
			if got.Checksum != "osv-scanner_SHA256SUMS" {
				t.Fatalf("checksum %s", got.Checksum)
			}
			dest := "osv-scanner"
			if tc.p.GOOS == "windows" {
				dest = "osv-scanner.exe"
			}
			if got.DestName != dest {
				t.Fatalf("dest %s", got.DestName)
			}
		})
	}
	if _, err := osvScannerAsset(OSVScannerVersion, Platform{GOOS: "linux", GOARCH: "386"}); err == nil {
		t.Fatal("osv-scanner linux/386 should fail")
	}
	if _, err := osvScannerAsset(OSVScannerVersion, Platform{GOOS: "darwin", GOARCH: "386"}); err == nil {
		t.Fatal("osv-scanner darwin/386 should fail")
	}
	if _, err := osvScannerAsset(OSVScannerVersion, Platform{GOOS: "linux", GOARCH: "arm"}); err == nil {
		t.Fatal("osv-scanner linux/arm should fail")
	}
}

func TestSelectWheelRealNames(t *testing.T) {
	t.Parallel()
	const py = "cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-"
	names := []string{
		"semgrep-" + SemgrepVersion + "-" + py + "macosx_10_14_x86_64.whl",
		"semgrep-" + SemgrepVersion + "-" + py + "macosx_11_0_arm64.whl",
		"semgrep-" + SemgrepVersion + "-" + py + "manylinux_2_34_aarch64.whl",
		"semgrep-" + SemgrepVersion + "-" + py + "manylinux_2_34_x86_64.whl",
		"semgrep-" + SemgrepVersion + "-" + py + "musllinux_1_2_aarch64.whl",
		"semgrep-" + SemgrepVersion + "-" + py + "musllinux_1_2_x86_64.whl",
		"semgrep-" + SemgrepVersion + "-" + py + "win_amd64.whl",
	}
	wheels := make([]Wheel, len(names))
	for i, name := range names {
		wheels[i] = Wheel{Filename: name, URL: "https://files.example/" + name, SHA256: "abc"}
	}

	cases := []struct {
		p    Platform
		want string
	}{
		{Platform{GOOS: "darwin", GOARCH: "amd64"}, "macosx_10_14_x86_64.whl"},
		{Platform{GOOS: "darwin", GOARCH: "arm64"}, "macosx_11_0_arm64.whl"},
		{Platform{GOOS: "linux", GOARCH: "amd64", Libc: "glibc"}, "manylinux_2_34_x86_64.whl"},
		{Platform{GOOS: "linux", GOARCH: "arm64", Libc: "glibc"}, "manylinux_2_34_aarch64.whl"},
		{Platform{GOOS: "linux", GOARCH: "amd64", Libc: "musl"}, "musllinux_1_2_x86_64.whl"},
		{Platform{GOOS: "linux", GOARCH: "arm64", Libc: "musl"}, "musllinux_1_2_aarch64.whl"},
		{Platform{GOOS: "windows", GOARCH: "amd64"}, "win_amd64.whl"},
	}
	for _, tc := range cases {
		t.Run(tc.p.String(), func(t *testing.T) {
			t.Parallel()
			got, err := SelectWheel(wheels, tc.p)
			if err != nil {
				t.Fatal(err)
			}
			if got.Filename[len(got.Filename)-len(tc.want):] != tc.want {
				t.Fatalf("got %s", got.Filename)
			}
		})
	}
	if _, err := SelectWheel(wheels, Platform{GOOS: "linux", GOARCH: "ppc64le", Libc: "glibc"}); err == nil {
		t.Fatal("expected no wheel")
	}
}

func TestDetectLibc(t *testing.T) {
	got := detectLibc()
	if runtime.GOOS == "linux" {
		if got != "glibc" && got != "musl" {
			t.Fatalf("libc %q", got)
		}
		return
	}
	if got != "" {
		t.Fatalf("libc %q", got)
	}
}

func TestOptionalScannerAssets(t *testing.T) {
	t.Parallel()
	gosecCases := []Platform{
		{GOOS: "linux", GOARCH: "amd64"},
		{GOOS: "linux", GOARCH: "s390x"},
		{GOOS: "darwin", GOARCH: "arm64"},
		{GOOS: "windows", GOARCH: "arm64"},
	}
	for _, p := range gosecCases {
		got, err := gosecAsset(GosecVersion, p)
		if err != nil {
			t.Fatalf("gosec %s: %v", p, err)
		}
		want := fmt.Sprintf("gosec_%s_%s_%s.tar.gz", GosecVersion, p.GOOS, p.GOARCH)
		if got.Asset != want || got.Checksum != fmt.Sprintf("gosec_%s_checksums.txt", GosecVersion) {
			t.Fatalf("gosec %s %+v", p, got)
		}
		if got.Binary != exeName("gosec", p.GOOS) {
			t.Fatalf("gosec binary %+v", got)
		}
	}
	if _, err := gosecAsset(GosecVersion, Platform{GOOS: "linux", GOARCH: "386"}); err == nil {
		t.Fatal("gosec linux/386 should fail")
	}

	hadolintCases := []struct {
		p    Platform
		want string
	}{
		{Platform{GOOS: "linux", GOARCH: "amd64"}, "hadolint-linux-x86_64"},
		{Platform{GOOS: "linux", GOARCH: "arm64"}, "hadolint-linux-arm64"},
		{Platform{GOOS: "darwin", GOARCH: "amd64"}, "hadolint-macos-x86_64"},
		{Platform{GOOS: "darwin", GOARCH: "arm64"}, "hadolint-macos-arm64"},
		{Platform{GOOS: "windows", GOARCH: "amd64"}, "hadolint-windows-x86_64.exe"},
	}
	for _, tc := range hadolintCases {
		got, err := hadolintAsset(HadolintVersion, tc.p)
		if err != nil {
			t.Fatalf("hadolint %s: %v", tc.p, err)
		}
		if got.Asset != tc.want || !got.Raw || got.Checksum != "checksums.sha256" {
			t.Fatalf("hadolint %s %+v", tc.p, got)
		}
		if got.DestName != exeName("hadolint", tc.p.GOOS) {
			t.Fatalf("hadolint dest %+v", got)
		}
	}
	if _, err := hadolintAsset(HadolintVersion, Platform{GOOS: "windows", GOARCH: "arm64"}); err == nil {
		t.Fatal("hadolint windows/arm64 should fail")
	}

	zizmorCases := []struct {
		p    Platform
		want string
	}{
		{Platform{GOOS: "linux", GOARCH: "amd64"}, "zizmor-x86_64-unknown-linux-gnu.tar.gz"},
		{Platform{GOOS: "linux", GOARCH: "arm64"}, "zizmor-aarch64-unknown-linux-gnu.tar.gz"},
		{Platform{GOOS: "darwin", GOARCH: "amd64"}, "zizmor-x86_64-apple-darwin.tar.gz"},
		{Platform{GOOS: "darwin", GOARCH: "arm64"}, "zizmor-aarch64-apple-darwin.tar.gz"},
		{Platform{GOOS: "windows", GOARCH: "amd64"}, "zizmor-x86_64-pc-windows-msvc.zip"},
	}
	for _, tc := range zizmorCases {
		got, err := zizmorAsset(ZizmorVersion, tc.p)
		if err != nil {
			t.Fatalf("zizmor %s: %v", tc.p, err)
		}
		if got.Asset != tc.want || len(got.SHA256) != 64 || got.Checksum != "" {
			t.Fatalf("zizmor %s %+v", tc.p, got)
		}
		if got.Binary != exeName("zizmor", tc.p.GOOS) {
			t.Fatalf("zizmor binary %+v", got)
		}
	}
	if _, err := zizmorAsset(ZizmorVersion, Platform{GOOS: "windows", GOARCH: "arm64"}); err == nil {
		t.Fatal("zizmor windows/arm64 should fail")
	}
	if len(zizmorChecksums) != len(zizmorCases) {
		t.Fatalf("zizmor checksum pins %d, platforms %d", len(zizmorChecksums), len(zizmorCases))
	}
}

func TestSupplyChainToolAssets(t *testing.T) {
	t.Parallel()
	sc, err := scorecardAsset(ScorecardVersion, Platform{GOOS: "windows", GOARCH: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if sc.Asset != fmt.Sprintf("scorecard_%s_windows_arm64.tar.gz", ScorecardVersion) || sc.Checksum != "scorecard_checksums.txt" || sc.Binary != "scorecard.exe" {
		t.Fatalf("scorecard %+v", sc)
	}
	th, err := trufflehogAsset(TrufflehogVersion, Platform{GOOS: "linux", GOARCH: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if th.Asset != fmt.Sprintf("trufflehog_%s_linux_amd64.tar.gz", TrufflehogVersion) || th.Checksum != fmt.Sprintf("trufflehog_%s_checksums.txt", TrufflehogVersion) {
		t.Fatalf("trufflehog %+v", th)
	}
	if _, err := trufflehogAsset(TrufflehogVersion, Platform{GOOS: "linux", GOARCH: "386"}); err == nil {
		t.Fatal("trufflehog linux/386 should fail")
	}
	cases := map[Platform]string{
		{GOOS: "linux", GOARCH: "amd64"}:   "cosign-linux-amd64",
		{GOOS: "linux", GOARCH: "arm"}:     "cosign-linux-arm",
		{GOOS: "linux", GOARCH: "s390x"}:   "cosign-linux-s390x",
		{GOOS: "darwin", GOARCH: "arm64"}:  "cosign-darwin-arm64",
		{GOOS: "windows", GOARCH: "amd64"}: "cosign-windows-amd64.exe",
	}
	for p, want := range cases {
		got, err := cosignAsset(CosignVersion, p)
		if err != nil {
			t.Fatalf("cosign %s: %v", p, err)
		}
		if got.Asset != want || !got.Raw || got.Checksum != "cosign_checksums.txt" || got.DestName != exeName("cosign", p.GOOS) {
			t.Fatalf("cosign %s %+v", p, got)
		}
	}
	if _, err := cosignAsset(CosignVersion, Platform{GOOS: "windows", GOARCH: "arm64"}); err == nil {
		t.Fatal("cosign windows/arm64 should fail")
	}
	if _, err := cosignAsset(CosignVersion, Platform{GOOS: "linux", GOARCH: "arm", GOARM: "6"}); err == nil {
		t.Fatal("cosign armv6 should fail")
	}
}

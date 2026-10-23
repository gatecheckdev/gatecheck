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

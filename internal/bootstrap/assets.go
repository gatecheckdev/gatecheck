package bootstrap

import (
	"fmt"
	"strings"
)

type githubAsset struct {
	Asset    string
	Checksum string
	Binary   string
	DestName string
	// Raw means the release asset is the binary itself, not an archive.
	Raw bool
	// SHA256 is a pinned digest for releases that publish no checksum file.
	// When it is set, Checksum is not downloaded.
	SHA256 string
}

func grypeAsset(version string, p Platform) (githubAsset, error) {
	if !grypeSupported(p) {
		return githubAsset{}, unsupported("grype", p)
	}
	return anchoreAsset("grype", version, p), nil
}

func syftAsset(version string, p Platform) (githubAsset, error) {
	if !syftSupported(p) {
		return githubAsset{}, unsupported("syft", p)
	}
	return anchoreAsset("syft", version, p), nil
}

func anchoreAsset(name, version string, p Platform) githubAsset {
	ext := "tar.gz"
	if p.GOOS == "windows" {
		ext = "zip"
	}
	asset := fmt.Sprintf("%s_%s_%s_%s.%s", name, version, p.GOOS, p.GOARCH, ext)
	return githubAsset{
		Asset:    asset,
		Checksum: fmt.Sprintf("%s_%s_checksums.txt", name, version),
		Binary:   exeName(name, p.GOOS),
		DestName: exeName(name, p.GOOS),
	}
}

func grypeSupported(p Platform) bool {
	switch p.GOOS {
	case "darwin":
		return p.GOARCH == "amd64" || p.GOARCH == "arm64"
	case "linux":
		switch p.GOARCH {
		case "amd64", "arm64", "ppc64le", "s390x":
			return true
		default:
			return false
		}
	case "windows":
		return p.GOARCH == "amd64"
	default:
		return false
	}
}

func syftSupported(p Platform) bool {
	switch p.GOOS {
	case "darwin":
		return p.GOARCH == "amd64" || p.GOARCH == "arm64"
	case "linux":
		switch p.GOARCH {
		case "amd64", "arm64", "ppc64le", "riscv64", "s390x":
			return true
		default:
			return false
		}
	case "windows":
		return p.GOARCH == "amd64" || p.GOARCH == "arm64"
	default:
		return false
	}
}

func gitleaksAsset(version string, p Platform) (githubAsset, error) {
	arch, ok := gitleaksArch(p)
	if !ok || !gitleaksOSArch(p.GOOS, arch) {
		return githubAsset{}, unsupported("gitleaks", p)
	}
	ext := "tar.gz"
	if p.GOOS == "windows" {
		ext = "zip"
	}
	asset := fmt.Sprintf("gitleaks_%s_%s_%s.%s", version, p.GOOS, arch, ext)
	return githubAsset{
		Asset:    asset,
		Checksum: fmt.Sprintf("gitleaks_%s_checksums.txt", version),
		Binary:   exeName("gitleaks", p.GOOS),
		DestName: exeName("gitleaks", p.GOOS),
	}, nil
}

func gitleaksArch(p Platform) (string, bool) {
	switch p.GOARCH {
	case "amd64":
		return "x64", true
	case "386":
		return "x32", true
	case "arm64":
		return "arm64", true
	case "arm":
		switch p.GOARM {
		case "", "7":
			return "armv7", true
		case "6":
			return "armv6", true
		default:
			return "", false
		}
	default:
		return "", false
	}
}

func gitleaksOSArch(goos, arch string) bool {
	switch goos {
	case "darwin":
		return arch == "x64" || arch == "arm64"
	case "linux":
		switch arch {
		case "x64", "x32", "arm64", "armv6", "armv7":
			return true
		default:
			return false
		}
	case "windows":
		return arch == "x64" || arch == "x32" || arch == "arm64"
	default:
		return false
	}
}

func trivyAsset(version string, p Platform) (githubAsset, error) {
	osName, archName, ok := trivyOSArch(p)
	if !ok {
		return githubAsset{}, unsupported("trivy", p)
	}
	ext := "tar.gz"
	if p.GOOS == "windows" {
		ext = "zip"
	}
	asset := fmt.Sprintf("trivy_%s_%s-%s.%s", version, osName, archName, ext)
	return githubAsset{
		Asset:    asset,
		Checksum: fmt.Sprintf("trivy_%s_checksums.txt", version),
		Binary:   exeName("trivy", p.GOOS),
		DestName: exeName("trivy", p.GOOS),
	}, nil
}

func trivyOSArch(p Platform) (string, string, bool) {
	var osName string
	switch p.GOOS {
	case "linux":
		osName = "Linux"
	case "darwin":
		osName = "macOS"
	case "windows":
		osName = "windows"
	case "freebsd":
		osName = "FreeBSD"
	default:
		return "", "", false
	}

	var archName string
	switch p.GOARCH {
	case "amd64":
		archName = "64bit"
	case "386":
		archName = "32bit"
	case "arm":
		if p.GOARM != "" && p.GOARM != "7" {
			return "", "", false
		}
		archName = "ARM"
	case "arm64":
		archName = "ARM64"
	case "ppc64le":
		archName = "PPC64LE"
	case "s390x":
		archName = "s390x"
	default:
		return "", "", false
	}

	switch p.GOOS {
	case "linux":
		switch p.GOARCH {
		case "386", "amd64", "arm", "arm64", "ppc64le", "s390x":
			return osName, archName, true
		default:
			return "", "", false
		}
	case "darwin":
		if p.GOARCH == "amd64" || p.GOARCH == "arm64" {
			return osName, archName, true
		}
	case "windows":
		if p.GOARCH == "amd64" {
			return osName, archName, true
		}
	case "freebsd":
		if p.GOARCH == "amd64" {
			return osName, archName, true
		}
	}
	return "", "", false
}

func osvScannerAsset(version string, p Platform) (githubAsset, error) {
	goos, arch, ok := osvOSArch(p)
	if !ok {
		return githubAsset{}, unsupported("osv-scanner", p)
	}
	asset := fmt.Sprintf("osv-scanner_%s_%s", goos, arch)
	if p.GOOS == "windows" {
		asset += ".exe"
	}
	return githubAsset{
		Asset:    asset,
		Checksum: "osv-scanner_SHA256SUMS",
		Binary:   asset,
		DestName: exeName("osv-scanner", p.GOOS),
		Raw:      true,
	}, nil
}

func osvOSArch(p Platform) (string, string, bool) {
	switch p.GOOS {
	case "darwin", "linux", "windows":
	default:
		return "", "", false
	}
	switch p.GOARCH {
	case "amd64", "arm64":
		return p.GOOS, p.GOARCH, true
	default:
		return "", "", false
	}
}

func gosecAsset(version string, p Platform) (githubAsset, error) {
	if !gosecSupported(p) {
		return githubAsset{}, unsupported("gosec", p)
	}
	// gosec ships tar.gz archives on every platform, Windows included.
	return githubAsset{
		Asset:    fmt.Sprintf("gosec_%s_%s_%s.tar.gz", version, p.GOOS, p.GOARCH),
		Checksum: fmt.Sprintf("gosec_%s_checksums.txt", version),
		Binary:   exeName("gosec", p.GOOS),
		DestName: exeName("gosec", p.GOOS),
	}, nil
}

func gosecSupported(p Platform) bool {
	switch p.GOOS {
	case "darwin", "windows":
		return p.GOARCH == "amd64" || p.GOARCH == "arm64"
	case "linux":
		switch p.GOARCH {
		case "amd64", "arm64", "ppc64le", "s390x":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func hadolintAsset(_ string, p Platform) (githubAsset, error) {
	var osName string
	switch p.GOOS {
	case "linux":
		osName = "linux"
	case "darwin":
		osName = "macos"
	case "windows":
		osName = "windows"
	default:
		return githubAsset{}, unsupported("hadolint", p)
	}
	var arch string
	switch p.GOARCH {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "arm64"
	default:
		return githubAsset{}, unsupported("hadolint", p)
	}
	if p.GOOS == "windows" && arch != "x86_64" {
		return githubAsset{}, unsupported("hadolint", p)
	}
	asset := fmt.Sprintf("hadolint-%s-%s", osName, arch)
	if p.GOOS == "windows" {
		asset += ".exe"
	}
	return githubAsset{
		Asset:    asset,
		Checksum: "checksums.sha256",
		Binary:   asset,
		DestName: exeName("hadolint", p.GOOS),
		Raw:      true,
	}, nil
}

func zizmorAsset(_ string, p Platform) (githubAsset, error) {
	var arch string
	switch p.GOARCH {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	default:
		return githubAsset{}, unsupported("zizmor", p)
	}
	var asset string
	switch p.GOOS {
	case "darwin":
		asset = fmt.Sprintf("zizmor-%s-apple-darwin.tar.gz", arch)
	case "linux":
		asset = fmt.Sprintf("zizmor-%s-unknown-linux-gnu.tar.gz", arch)
	case "windows":
		asset = fmt.Sprintf("zizmor-%s-pc-windows-msvc.zip", arch)
	default:
		return githubAsset{}, unsupported("zizmor", p)
	}
	sum, ok := zizmorChecksums[asset]
	if !ok {
		return githubAsset{}, unsupported("zizmor", p)
	}
	return githubAsset{
		Asset:    asset,
		Binary:   exeName("zizmor", p.GOOS),
		DestName: exeName("zizmor", p.GOOS),
		SHA256:   sum,
	}, nil
}

func exeName(name, goos string) string {
	if goos == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
		return name + ".exe"
	}
	return name
}

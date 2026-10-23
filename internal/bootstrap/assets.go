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

func exeName(name, goos string) string {
	if goos == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
		return name + ".exe"
	}
	return name
}

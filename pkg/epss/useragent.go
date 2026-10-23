package epss

import (
	"fmt"
	"runtime/debug"
	"strings"
	"sync/atomic"
)

const projectURL = "https://github.com/gatecheckdev/gatecheck"

var productVersion atomic.Value // string

func init() {
	productVersion.Store(moduleVersion())
}

// SetVersion records the gatecheck version used in the EPSS User-Agent.
// Empty and placeholder values are ignored.
func SetVersion(version string) {
	trimmed := strings.TrimSpace(version)
	if trimmed == "" || trimmed == "[Not Provided]" || strings.EqualFold(trimmed, "unknown") {
		return
	}
	cleaned := cleanVersion(trimmed)
	if cleaned == "" {
		return
	}
	productVersion.Store(cleaned)
}

func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "unknown"
	}
	cleaned := cleanVersion(info.Main.Version)
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}

func cleanVersion(version string) string {
	version = strings.Map(func(r rune) rune {
		if r <= 32 || r >= 127 {
			return -1
		}
		return r
	}, version)
	if len(version) > 80 {
		version = version[:80]
	}
	return version
}

// UserAgent returns the User-Agent header value used for gatecheck HTTP requests.
func UserAgent() string {
	version, _ := productVersion.Load().(string)
	if version == "" {
		version = "unknown"
	}
	return fmt.Sprintf("gatecheck/%s (+%s)", version, projectURL)
}

func userAgent() string {
	return UserAgent()
}

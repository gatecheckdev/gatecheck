package bootstrap

import (
	"debug/elf"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
)

// Platform is the OS, architecture, and Linux libc a release asset is chosen for.
type Platform struct {
	GOOS   string
	GOARCH string
	GOARM  string
	Libc   string
}

func (p Platform) String() string {
	arch := p.GOARCH
	if p.GOARCH == "arm" && p.GOARM != "" {
		arch = "armv" + p.GOARM
	}
	text := p.GOOS + "/" + arch
	if p.GOOS == "linux" && p.Libc != "" {
		text += " (" + p.Libc + ")"
	}
	return text
}

func currentPlatform() Platform {
	return Platform{
		GOOS:   runtime.GOOS,
		GOARCH: runtime.GOARCH,
		GOARM:  buildSetting("GOARM"),
		Libc:   detectLibc(),
	}
}

func buildSetting(key string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return ""
}

func detectLibc() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	file, err := elf.Open("/proc/self/exe")
	if err != nil {
		return "glibc"
	}
	defer func() { _ = file.Close() }()
	for _, prog := range file.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		reader := prog.Open()
		buf, err := io.ReadAll(io.LimitReader(reader, 256))
		if err != nil && len(buf) == 0 {
			return "glibc"
		}
		interp := string(buf)
		if strings.Contains(interp, "musl") {
			return "musl"
		}
		return "glibc"
	}
	return "glibc"
}

func (p Platform) exe(name string) string {
	if p.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
		return name + ".exe"
	}
	return name
}

func unsupported(tool string, p Platform) error {
	return fmt.Errorf("%s has no published release asset for %s", tool, p)
}

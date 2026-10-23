package bootstrap

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/gatecheckdev/gatecheck/internal/fetch"
)

// Wheel is one file from the PyPI JSON "urls" list.
type Wheel struct {
	Filename string
	URL      string
	SHA256   string
}

type pypiFile struct {
	Filename    string `json:"filename"`
	URL         string `json:"url"`
	Packagetype string `json:"packagetype"`
	Digests     struct {
		SHA256 string `json:"sha256"`
	} `json:"digests"`
}

type pypiIndex struct {
	URLs []pypiFile `json:"urls"`
}

// SelectWheel picks the semgrep wheel for the platform.
// Linux glibc uses manylinux; Linux musl uses musllinux.
func SelectWheel(wheels []Wheel, p Platform) (Wheel, error) {
	match := wheelMatch(p)
	if match == nil {
		return Wheel{}, errNoWheel
	}
	var found []Wheel
	for _, wheel := range wheels {
		if match(wheel.Filename) {
			found = append(found, wheel)
		}
	}
	if len(found) == 0 {
		return Wheel{}, errNoWheel
	}
	for _, wheel := range found {
		name := wheel.Filename
		if strings.Contains(name, "manylinux_2_34") || strings.Contains(name, "musllinux_1_2") || strings.Contains(name, "win_amd64") || strings.Contains(name, "macosx_") {
			return wheel, nil
		}
	}
	return found[0], nil
}

func wheelMatch(p Platform) func(string) bool {
	switch {
	case p.GOOS == "darwin" && p.GOARCH == "amd64":
		return func(name string) bool {
			return strings.Contains(name, "macosx") && strings.Contains(name, "x86_64")
		}
	case p.GOOS == "darwin" && p.GOARCH == "arm64":
		return func(name string) bool {
			return strings.Contains(name, "macosx") && strings.Contains(name, "arm64")
		}
	case p.GOOS == "linux" && p.GOARCH == "amd64" && p.Libc == "musl":
		return func(name string) bool {
			return strings.Contains(name, "musllinux") && strings.Contains(name, "x86_64")
		}
	case p.GOOS == "linux" && p.GOARCH == "arm64" && p.Libc == "musl":
		return func(name string) bool {
			return strings.Contains(name, "musllinux") && strings.Contains(name, "aarch64")
		}
	case p.GOOS == "linux" && p.GOARCH == "amd64":
		return func(name string) bool {
			return strings.Contains(name, "manylinux") && strings.Contains(name, "x86_64")
		}
	case p.GOOS == "linux" && p.GOARCH == "arm64":
		return func(name string) bool {
			return strings.Contains(name, "manylinux") && strings.Contains(name, "aarch64")
		}
	case p.GOOS == "windows" && p.GOARCH == "amd64":
		return func(name string) bool {
			return strings.Contains(name, "win_amd64")
		}
	default:
		return nil
	}
}

var errNoWheel = errors.New("no semgrep wheel for this platform")

func wheelSkipMessage(p Platform) string {
	return fmt.Sprintf("semgrep: no PyPI wheel for %s; osemgrep wheels are published for macOS (x86_64, arm64), Linux glibc and musl (x86_64, aarch64), and Windows amd64", p)
}

func extractOsemgrep(wheelPath, destDir string, windows bool) error {
	zr, err := zip.OpenReader(wheelPath)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()

	var core *zip.File
	type libFile struct {
		file *zip.File
		rel  string
	}
	var libs []libFile
	for _, file := range zr.File {
		if !file.Mode().IsRegular() {
			continue
		}
		name := path.Clean(strings.TrimPrefix(file.Name, "./"))
		if isSemgrepCore(name) {
			if core != nil {
				return errors.New("wheel contains more than one semgrep-core binary")
			}
			core = file
			continue
		}
		rel, ok := semgrepLibRel(name)
		if !ok {
			continue
		}
		libs = append(libs, libFile{file: file, rel: rel})
	}
	if core == nil {
		return errNoSemgrepCore
	}
	if core.UncompressedSize64 > uint64(maxExtractBytes) {
		return fmt.Errorf("semgrep-core exceeds %d bytes", maxExtractBytes)
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	binaryName := "semgrep-core"
	if windows {
		binaryName = "osemgrep.exe"
	}
	rc, err := core.Open()
	if err != nil {
		return err
	}
	err = fetch.AtomicWrite(filepath.Join(destDir, binaryName), rc, 0o755)
	_ = rc.Close()
	if err != nil {
		return err
	}

	for _, lib := range libs {
		if lib.file.UncompressedSize64 > uint64(maxExtractBytes) {
			return fmt.Errorf("%s exceeds %d bytes", lib.rel, maxExtractBytes)
		}
		dest, err := safeJoin(filepath.Join(destDir, "libs"), lib.rel)
		if err != nil {
			return err
		}
		rc, err := lib.file.Open()
		if err != nil {
			return err
		}
		err = fetch.AtomicWrite(dest, rc, 0o644)
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

var errNoSemgrepCore = errors.New("wheel does not contain semgrep-core")

func isSemgrepCore(name string) bool {
	base := path.Base(name)
	if base != "semgrep-core" && base != "semgrep-core.exe" {
		return false
	}
	dir := path.Dir(name)
	return dir == "semgrep/bin" || strings.HasSuffix(dir, "/semgrep/bin")
}

func semgrepLibRel(name string) (string, bool) {
	const marker = "semgrep/bin/libs/"
	idx := strings.Index(name, marker)
	if idx < 0 {
		return "", false
	}
	rel := name[idx+len(marker):]
	if rel == "" || strings.HasSuffix(rel, "/") {
		return "", false
	}
	return rel, true
}

func safeJoin(root, rel string) (string, error) {
	rel = path.Clean(rel)
	if rel == "." || rel == "" || strings.HasPrefix(rel, "..") || path.IsAbs(rel) {
		return "", fmt.Errorf("unsafe path %q", rel)
	}
	dest := filepath.Join(root, filepath.FromSlash(rel))
	rootClean := filepath.Clean(root)
	if dest != rootClean && !strings.HasPrefix(dest, rootClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe path %q", rel)
	}
	return dest, nil
}

func decodeWheels(data []byte) ([]Wheel, error) {
	var index pypiIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("parse semgrep pypi json: %w", err)
	}
	wheels := make([]Wheel, 0, len(index.URLs))
	for _, file := range index.URLs {
		if file.Packagetype != "" && file.Packagetype != "bdist_wheel" {
			continue
		}
		if !strings.HasSuffix(file.Filename, ".whl") {
			continue
		}
		wheels = append(wheels, Wheel{
			Filename: file.Filename,
			URL:      file.URL,
			SHA256:   file.Digests.SHA256,
		})
	}
	if len(wheels) == 0 {
		return nil, errors.New("semgrep pypi json has no wheels")
	}
	return wheels, nil
}

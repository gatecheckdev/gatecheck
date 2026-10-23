package gatecheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"

	"github.com/easy-up/go-coverage"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
)

// KindForList is the report type used by list and list-all.
func KindForList(content []byte, filename string) artifacts.ReportKind {
	return resolveKind(content, filename, true)
}

func resolveKind(content []byte, filename string, listRules bool) artifacts.ReportKind {
	if isGatecheckBundle(content) {
		return artifacts.KindBundle
	}
	if kind := artifacts.Detect(content); kind != artifacts.KindUnknown {
		return kind
	}
	return kindFromFilename(filename, listRules)
}

// ListAllAction reports whether list-all should print the file, and whether EPSS columns apply.
// Coverage files are skipped. list still prints them.
func ListAllAction(content []byte, filename string) (supported bool, withEPSS bool) {
	kind := KindForList(content, filename)
	if kind == artifacts.KindUnknown || kind.IsCoverage() {
		return false, false
	}
	return true, kind == artifacts.KindGrype || kind == artifacts.KindCycloneDX
}

func kindFromFilename(name string, listRules bool) artifacts.ReportKind {
	switch {
	case strings.Contains(name, "grype"):
		return artifacts.KindGrype
	case strings.Contains(name, "cyclonedx"):
		return artifacts.KindCycloneDX
	case strings.Contains(name, "semgrep"):
		return artifacts.KindSemgrep
	case strings.Contains(name, "gitleaks"):
		return artifacts.KindGitleaks
	case strings.Contains(name, "syft"):
		return artifacts.KindSyft
	case strings.Contains(name, "sarif"):
		return artifacts.KindSARIF
	case strings.Contains(name, "bundle") || (listRules && strings.Contains(name, "gatecheck")):
		return artifacts.KindBundle
	case artifacts.IsCoverageReport(name):
		return coverageKindFromName(name)
	default:
		return artifacts.KindUnknown
	}
}

func coverageKindFromName(name string) artifacts.ReportKind {
	switch {
	case strings.Contains(name, "lcov") || strings.HasSuffix(name, ".info"):
		return artifacts.KindLCOV
	case strings.Contains(name, "clover"):
		return artifacts.KindClover
	case strings.HasSuffix(name, ".xml"):
		return artifacts.KindCobertura
	default:
		return artifacts.KindCoverage
	}
}

func isGatecheckBundle(content []byte) bool {
	if len(content) < 2 || content[0] != 0x1f || content[1] != 0x8b {
		return false
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return false
	}
	defer func() { _ = gzipReader.Close() }()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err != nil {
			return false
		}
		if header.Name == archive.ManifestFilename || strings.HasSuffix(header.Name, "/"+archive.ManifestFilename) {
			return true
		}
	}
}

func coverageMode(kind artifacts.ReportKind, filename string) (coverage.CoverageMode, error) {
	switch kind {
	case artifacts.KindLCOV:
		return coverage.LCOV, nil
	case artifacts.KindClover:
		return coverage.CLOVER, nil
	case artifacts.KindCobertura:
		return coverage.COBERTURA, nil
	default:
		return artifacts.GetCoverageMode(filename)
	}
}

// readReport buffers a report so the type can be detected and the bytes decoded.
func readReport(src io.Reader) ([]byte, error) {
	return io.ReadAll(src)
}

package gatecheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
)

func List(dst io.Writer, src io.Reader, inputFilename string) error {
	var decoder interface {
		Decode(any) error
	}
	var report interface {
		String() string
	}

	decoder = json.NewDecoder(src)

	switch {
	case strings.Contains(inputFilename, "grype"):
		slog.Debug("list", "filename", inputFilename, "filetype", "grype")
		report = &grype.ScanReport{}

	case strings.Contains(inputFilename, "semgrep"):
		slog.Debug("list", "filename", inputFilename, "filetype", "semgrep")
		report = &semgrep.ScanReport{}

	case strings.Contains(inputFilename, "gitleaks"):
		slog.Debug("list", "filename", inputFilename, "filetype", "gitleaks")
		report = &gitleaks.ScanReport{}

	case strings.Contains(inputFilename, "syft"):
		slog.Debug("list", "filename", inputFilename, "filetype", "syft")
		slog.Warn("syft decoder is not supported yet")
		return nil

	case strings.Contains(inputFilename, "cyclonedx"):
		slog.Debug("list", "filename", inputFilename, "filetype", "cyclonedx")
		report = &cyclonedx.ScanReport{}

	case strings.Contains(inputFilename, "bundle"):
		slog.Debug("list", "filename", inputFilename, "filetype", "bundle")
		slog.Warn("gatecheck bundle decoder is not supported yet")
		return nil

	default:
		slog.Error("invalid input filetype", "filename", inputFilename)
		return errors.New("failed to list artifact content")
	}

	if err := decoder.Decode(report); err != nil {
		slog.Error("list decode", "error", err)
		return errors.New("failed to decode report")
	}

	_, err := fmt.Fprintln(dst, report.String())
	return err
}

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

// Validate against config thresholds
func Validate(config map[string]any, targetSrc io.Reader, targetfilename string) error {

	var decoder interface {
		Decode(any) error
	}
	decoder = json.NewDecoder(targetSrc)

	switch {
	case strings.Contains(targetfilename, "grype"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "grype")
		report := &grype.ScanReport{}
		if err := decoder.Decode(report); err != nil {
			slog.Error("error decoding grype report during validation", "error", err)
			return errors.New("failed to decode report")
		}
		return validateGrype(config, report)

	case strings.Contains(targetfilename, "semgrep"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "semgrep")
		report := &semgrep.ScanReport{}
		if err := decoder.Decode(report); err != nil {
			slog.Error("error decoding grype report during validation", "error", err)
			return errors.New("failed to decode report")
		}

	case strings.Contains(targetfilename, "gitleaks"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "gitleaks")
		report := &gitleaks.ScanReport{}
		if err := decoder.Decode(report); err != nil {
			slog.Error("error decoding grype report during validation", "error", err)
			return errors.New("failed to decode report")
		}

	case strings.Contains(targetfilename, "syft"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "syft")
		slog.Warn("syft decoder is not supported yet")
		return nil

	case strings.Contains(targetfilename, "cyclonedx"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "cyclonedx")
		report := &cyclonedx.ScanReport{}
		if err := decoder.Decode(report); err != nil {
			slog.Error("error decoding grype report during validation", "error", err)
			return errors.New("failed to decode report")
		}

	case strings.Contains(targetfilename, "bundle"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "bundle")
		// bundle, err := archive.UntarGzipBundle(src)
		// if err != nil {
		// 	return err
		// }
		// _, err = fmt.Fprintln(dst, bundle.Content())
		return errors.New("bundle validation not yet supported.")

	default:
		slog.Error("invalid input filetype", "filename", targetfilename)
		return errors.New("failed to validate artifact content")
	}

	return nil
}

func validateGrype(config map[string]any, report *grype.ScanReport) error {
	fmt.Printf("%+v\n", config[grype.ConfigFieldName])
	return nil
}

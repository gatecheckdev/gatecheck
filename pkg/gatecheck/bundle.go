package gatecheck

import (
	"io"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"log/slog"
)

// CreateBundle create a new bundle with a file
//
// If the bundle already exist, use CreateBundle.
// this function will completely overwrite an existing bundle
func CreateBundle(dstBundle io.Writer, src io.Reader, label string, tags []string) error {
	slog.Debug("add to source file content to bundle", "label", label, "tags", tags)
	srcContent, err := io.ReadAll(src)
	if err != nil {
		return err
	}

	bundle := archive.NewBundle()
	bundle.Add(srcContent, label, tags)

	slog.Debug("write bundle")
	n, err := archive.TarGzipBundle(dstBundle, bundle)
	if err != nil {
		return err
	}

	slog.Info("bundle write success", "bytes_written", n, "label", label, "tags", tags)

	return nil
}

// AppendToBundle adds a file to an existing bundle
//
// If the bundle doesn't exist, use CreateBundle
func AppendToBundle(bundleRWS io.ReadWriteSeeker, src io.Reader, label string, tags []string) error {

	slog.Debug("load bundle")
	bundle, err := archive.UntarGzipBundle(bundleRWS)
	if err != nil {
		return err
	}

	slog.Debug("load source file")
	srcContent, err := io.ReadAll(src)
	if err != nil {
		return err
	}

	slog.Debug("add to source file content to bundle", "label", label, "tags", tags)
	bundle.Add(srcContent, label, tags)

	// Seek errors are unlikely so just capture for edge cases
	_, seekErr := bundleRWS.Seek(0, io.SeekStart)

	slog.Debug("write bundle", "seek_err", seekErr)
	n, err := archive.TarGzipBundle(bundleRWS, bundle)
	if err != nil {
		return err
	}

	slog.Info("bundle write success", "bytes_written", n, "label", label, "tags", tags)

	return nil
}

// RemoveFromBundle removes a file from an existing bundle
func RemoveFromBundle(bundleRWS io.ReadWriteSeeker, label string) error {
	slog.Debug("load bundle")
	bundle, err := archive.UntarGzipBundle(bundleRWS)
	if err != nil {
		return err
	}
	bundle.Remove(label)
	// Seek errors are unlikely so just capture for edge cases
	_, seekErr := bundleRWS.Seek(0, io.SeekStart)

	slog.Debug("write bundle", "seek_err", seekErr)
	n, err := archive.TarGzipBundle(bundleRWS, bundle)
	if err != nil {
		return err
	}

	slog.Info("bundle write after remove success", "bytes_written", n, "label", label)
	return nil
}

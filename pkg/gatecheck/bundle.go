package gatecheck

import (
	"bytes"
	"io"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/sagikazarmark/slog-shim"
)

func CreateBundle(dst io.Writer, src io.Reader, label string, tags []string) error {
	slog.Debug("add to source file content to bundle", "label", label, "tags", tags)
	srcContent, err := io.ReadAll(src)
	if err != nil {
		return err
	}

	bundle := archive.NewBundle()
	bundle.Add(srcContent, label, tags)

	slog.Debug("write bundle")
	n, err := archive.TarGzipBundle(dst, bundle)
	if err != nil {
		return err
	}

	slog.Info("bundle write success", "bytes_written", n, "label", label, "tags", tags)

	return nil

}

// AppendToBundle adds a file to an existing
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

// RmFromBundle removes a file from an existing bundle
func RmFromBundle(bundleRWS io.ReadWriteSeeker, label string) error {
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, bundleRWS); err != nil {
		return err
	}
	return nil
}

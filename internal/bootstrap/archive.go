package bootstrap

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/gatecheckdev/gatecheck/internal/fetch"
)

const maxExtractBytes int64 = 400 << 20

func extractBinary(archivePath, wantBase, dest string) error {
	switch {
	case strings.HasSuffix(archivePath, ".zip"):
		return extractZipBinary(archivePath, wantBase, dest)
	case strings.HasSuffix(archivePath, ".tar.gz"), strings.HasSuffix(archivePath, ".tgz"):
		return extractTarBinary(archivePath, wantBase, dest)
	default:
		return fmt.Errorf("unsupported archive %s", archivePath)
	}
}

func extractTarBinary(archivePath, wantBase, dest string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("archive does not contain %s", wantBase)
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if path.Base(hdr.Name) != wantBase || strings.Contains(hdr.Name, "..") {
			continue
		}
		if hdr.Size > maxExtractBytes {
			return fmt.Errorf("%s exceeds %d bytes", wantBase, maxExtractBytes)
		}
		return fetch.AtomicWrite(dest, tr, 0o755)
	}
}

func extractZipBinary(archivePath, wantBase, dest string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()

	for _, file := range zr.File {
		if !file.Mode().IsRegular() {
			continue
		}
		if path.Base(file.Name) != wantBase || strings.Contains(file.Name, "..") {
			continue
		}
		if file.UncompressedSize64 > uint64(maxExtractBytes) {
			return fmt.Errorf("%s exceeds %d bytes", wantBase, maxExtractBytes)
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		err = fetch.AtomicWrite(dest, rc, 0o755)
		_ = rc.Close()
		return err
	}
	return fmt.Errorf("archive does not contain %s", wantBase)
}

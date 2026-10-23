// Package fetch downloads files and checks SHA-256 digests.
//
// gatecheck bootstrap uses it for GitHub release assets and PyPI wheels.
// gatecheck update downloads its own release through pkg/update.
package fetch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	// MaxDownloadBytes is the largest response body DownloadToFile will write.
	MaxDownloadBytes int64 = 512 << 20

	defaultUserAgent = "gatecheck (+https://github.com/gatecheckdev/gatecheck)"
)

// ErrChecksumMismatch means the downloaded bytes do not match the expected SHA-256.
var ErrChecksumMismatch = errors.New("checksum mismatch")

// Get reads a small response body. limit caps the number of bytes kept.
func Get(ctx context.Context, client *http.Client, rawURL, userAgent string, limit int64) ([]byte, error) {
	body, err := open(ctx, client, rawURL, userAgent)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()

	if limit <= 0 {
		limit = 8 << 20
	}
	buf, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, fmt.Errorf("download %s: exceeds %d bytes", rawURL, limit)
	}
	return buf, nil
}

// DownloadToFile streams rawURL to dest and returns the lowercase SHA-256 hex digest.
// dest is replaced only after the body has been written to a temporary file in the same directory.
func DownloadToFile(ctx context.Context, client *http.Client, rawURL, dest, userAgent string) (string, error) {
	body, err := open(ctx, client, rawURL, userAgent)
	if err != nil {
		return "", err
	}
	defer func() { _ = body.Close() }()

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".fetch-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(body, MaxDownloadBytes+1))
	if err != nil {
		_ = tmp.Close()
		return "", err
	}
	if n > MaxDownloadBytes {
		_ = tmp.Close()
		return "", fmt.Errorf("download %s: exceeds %d bytes", rawURL, MaxDownloadBytes)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := Replace(tmpName, dest); err != nil {
		return "", err
	}
	committed = true
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// CheckSHA256 reports ErrChecksumMismatch when got and want are not the same SHA-256 hex digest.
func CheckSHA256(got, want string) error {
	got = strings.ToLower(strings.TrimSpace(got))
	want = strings.ToLower(strings.TrimSpace(want))
	if !isSHA256Hex(got) || !isSHA256Hex(want) || got != want {
		return fmt.Errorf("%w: got %s want %s", ErrChecksumMismatch, got, want)
	}
	return nil
}

// ParseChecksums reads GNU and BSD checksum lines ("hex  name", "hex *name", "hex name").
// Blank lines and lines starting with # are ignored. Keys are the filename token and its base name.
func ParseChecksums(data []byte) (map[string]string, error) {
	sums := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !isSHA256Hex(fields[0]) {
			return nil, fmt.Errorf("invalid checksum line %q", line)
		}
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name == "" {
			return nil, fmt.Errorf("invalid checksum line %q", line)
		}
		sum := strings.ToLower(fields[0])
		sums[name] = sum
		base := path.Base(name)
		if _, ok := sums[base]; !ok {
			sums[base] = sum
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(sums) == 0 {
		return nil, errors.New("checksum file is empty")
	}
	return sums, nil
}

// LookupChecksum finds the digest for an asset name or its base name.
func LookupChecksum(sums map[string]string, asset string) (string, bool) {
	if sum, ok := sums[asset]; ok {
		return sum, true
	}
	sum, ok := sums[path.Base(asset)]
	return sum, ok
}

// AtomicWrite writes r to dest via a temporary file in the same directory, then renames it into place.
func AtomicWrite(dest string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".partial-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return err
	}
	if mode != 0 {
		if err := tmp.Chmod(mode); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := Replace(tmpName, dest); err != nil {
		return err
	}
	committed = true
	return nil
}

// Replace renames src onto dest. An existing dest is removed when the first rename fails,
// which is what Windows requires.
func Replace(src, dest string) error {
	if err := os.Rename(src, dest); err == nil {
		return nil
	} else if rmErr := os.Remove(dest); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return err
	}
	return os.Rename(src, dest)
}

func open(ctx context.Context, client *http.Client, rawURL, userAgent string) (io.ReadCloser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(userAgent) == "" {
		userAgent = defaultUserAgent
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept-Encoding", "identity")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		return nil, fmt.Errorf("download %s: %s", rawURL, res.Status)
	}
	if res.ContentLength > MaxDownloadBytes {
		_ = res.Body.Close()
		return nil, fmt.Errorf("download %s: content length %d exceeds limit", rawURL, res.ContentLength)
	}
	return res.Body, nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

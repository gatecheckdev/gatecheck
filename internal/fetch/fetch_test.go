package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseChecksums(t *testing.T) {
	in := []byte("" +
		"# comment\n" +
		"\n" +
		"27eef17e42f0340af6582cdbc33ad18faf9f601c613ab81d2e1658a94cbc357f  grype_0.121.0_linux_amd64.tar.gz\n" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa *starred.tar.gz\n" +
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB path/base.bin\n")
	sums, err := ParseChecksums(in)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := LookupChecksum(sums, "grype_0.121.0_linux_amd64.tar.gz")
	if !ok || got != "27eef17e42f0340af6582cdbc33ad18faf9f601c613ab81d2e1658a94cbc357f" {
		t.Fatalf("grype checksum %q %v", got, ok)
	}
	if _, ok := LookupChecksum(sums, "starred.tar.gz"); !ok {
		t.Fatal("missing starred name")
	}
	sum, ok := LookupChecksum(sums, "base.bin")
	if !ok || sum != strings.Repeat("b", 64) {
		t.Fatalf("base checksum %q %v", sum, ok)
	}

	if _, err := ParseChecksums([]byte("not-a-checksum file\n")); err == nil {
		t.Fatal("expected invalid line error")
	}
	if _, err := ParseChecksums(nil); err == nil {
		t.Fatal("expected empty file error")
	}
}

func TestDownloadToFileAndChecksum(t *testing.T) {
	payload := []byte("gatecheck-bytes")
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		if r.URL.Path != "/file" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)

	dest := filepath.Join(t.TempDir(), "nested", "file")
	got, err := DownloadToFile(context.Background(), srv.Client(), srv.URL+"/file", dest, "gatecheck/test (+https://github.com/gatecheckdev/gatecheck)")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("sum %s", got)
	}
	if !strings.HasPrefix(ua, "gatecheck/") || strings.Contains(ua, "Go-http-client") {
		t.Fatalf("user agent %q", ua)
	}
	body, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body %q", body)
	}
	if err := CheckSHA256(got, want); err != nil {
		t.Fatal(err)
	}
	err = CheckSHA256(got, strings.Repeat("0", 64))
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("mismatch error %v", err)
	}

	entries, err := os.ReadDir(filepath.Dir(dest))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".fetch-") || strings.HasPrefix(entry.Name(), ".partial-") {
			t.Fatalf("leftover temp file %s", entry.Name())
		}
	}
}

func TestDownloadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	_, err := Get(context.Background(), srv.Client(), srv.URL, "", 1024)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error %v", err)
	}
}

func TestAtomicWriteMode(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "bin", "tool")
	if err := AtomicWrite(dest, strings.NewReader("hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("mode %s", info.Mode())
	}
	if got, err := os.ReadFile(dest); err != nil || string(got) != "hello" {
		t.Fatalf("content %q %v", got, err)
	}
}

package gatecheck

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gatecheckdev/gatecheck/pkg/epss"
)

func TestLoadEPSSFromLocalFileSkipsDownload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "epss.csv")
	csv := "#model_version:v2025.03.14,score_date:2026-10-22T00:00:00Z\ncve,epss,percentile\nCVE-2024-1234,0.42,0.84\n"
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	opts := defaultOptions()
	WithEPSSURL("http://127.0.0.1:1/epss")(opts)
	WithEPSSClient(&http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("unexpected request %s", r.URL)
		return nil, os.ErrClosed
	})})(opts)
	WithEPSSCacheDir(filepath.Join(dir, "cache"))(opts)
	opts.epssFile = f

	data := &epss.Data{}
	if err := loadDataFromFileOrAPI(data, opts); err != nil {
		t.Fatal(err)
	}
	if data.CVEs["CVE-2024-1234"].EPSS != "0.42" {
		t.Fatalf("cves %#v", data.CVEs)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("local file created a cache dir %s", entry.Name())
		}
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	listOpt, err := WithEPSS(f, "http://127.0.0.1:1/epss", WithEPSSCache(false))
	if err != nil {
		t.Fatal(err)
	}
	got := &listOptions{}
	listOpt(got)
	if got.epssData == nil || got.epssData.CVEs["CVE-2024-1234"].EPSS != "0.42" {
		t.Fatalf("list data %#v", got.epssData)
	}
}

func TestEPSSDownloadListAndValidateShareCache(t *testing.T) {
	var gets atomic.Int32
	payload := gzipString(t, "#model_version:v2025.03.14,score_date:2026-10-22T00:00:00Z\ncve,epss,percentile\nCVE-2024-1234,0.42,0.84\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/epss_scores-current.csv.gz":
			w.Header().Set("Location", "/epss_scores-2026-10-22.csv.gz")
			w.WriteHeader(http.StatusFound)
		case "/epss_scores-2026-10-22.csv.gz":
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			gets.Add(1)
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Timeout = 5 * time.Second

	dir := t.TempDir()
	url := srv.URL + "/epss_scores-current.csv.gz"
	opts := []optionFunc{WithEPSSURL(url), WithEPSSClient(client), WithEPSSCacheDir(dir)}

	var buf bytes.Buffer
	if err := DownloadEPSS(&buf, opts...); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "CVE-2024-1234,0.42,0.84") {
		t.Fatalf("download %q", buf.String())
	}

	listOpt, err := WithEPSS(nil, url, opts...)
	if err != nil {
		t.Fatal(err)
	}
	listed := &listOptions{}
	listOpt(listed)
	if listed.epssData.CVEs["CVE-2024-1234"].EPSS != "0.42" {
		t.Fatalf("list %#v", listed.epssData)
	}

	fetchOpts := defaultOptions()
	for _, opt := range opts {
		opt(fetchOpts)
	}
	data := &epss.Data{}
	if err := loadDataFromFileOrAPI(data, fetchOpts); err != nil {
		t.Fatal(err)
	}
	if data.CVEs["CVE-2024-1234"].EPSS != "0.42" {
		t.Fatalf("validate load %#v", data.CVEs)
	}
	if gets.Load() != 1 {
		t.Fatalf("full file downloads = %d, want 1", gets.Load())
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func gzipString(t *testing.T, plain string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := io.WriteString(zw, plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

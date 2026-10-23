package cmd

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEPSSDownloadCommandCachesAndKeepsFlags(t *testing.T) {
	t.Setenv("GATECHECK_EPSS_CACHE", "")
	t.Setenv("GATECHECK_EPSS_CACHE_DIR", "")
	t.Cleanup(func() {
		if p, ok := RuntimeConfig.EPSSNoCache.FlagValueP.(*bool); ok && p != nil {
			*p = false
		}
		if p, ok := RuntimeConfig.EPSSCacheDir.FlagValueP.(*string); ok && p != nil {
			*p = ""
		}
		if p, ok := RuntimeConfig.EPSSURL.FlagValueP.(*string); ok && p != nil {
			*p = ""
		}
	})

	var gets atomic.Int32
	payload := gzipCSV(t, "#model_version:v2025.03.14,score_date:2026-10-22T00:00:00Z\ncve,epss,percentile\nCVE-2024-1234,0.42,0.84\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if !strings.HasPrefix(ua, "gatecheck/") || !strings.Contains(ua, "https://github.com/gatecheckdev/gatecheck") || strings.Contains(ua, "Go-http-client") {
			http.Error(w, "bad user agent "+ua, http.StatusBadRequest)
			return
		}
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

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	origTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = origTransport })
	http.DefaultTransport = hostOnlyTransport{host: parsed.Host, base: origTransport}

	root := NewGatecheckCommand()
	for _, args := range [][]string{
		{"download", "epss"},
		{"list"},
		{"list-all"},
		{"validate"},
	} {
		command, _, err := root.Find(args)
		if err != nil {
			t.Fatal(err)
		}
		if command.Flags().Lookup("epss-no-cache") == nil || command.Flags().Lookup("epss-cache-dir") == nil {
			t.Fatalf("%s is missing an EPSS cache flag", strings.Join(args, " "))
		}
	}
	download, _, err := root.Find([]string{"download", "epss"})
	if err != nil {
		t.Fatal(err)
	}
	if download.Flags().Lookup("epss-url") == nil {
		t.Fatal("missing --epss-url")
	}
	list, _, err := root.Find([]string{"list"})
	if err != nil {
		t.Fatal(err)
	}
	if list.Flags().Lookup("epss-filename") == nil || list.Flags().Lookup("epss-url") == nil {
		t.Fatal("list lost an existing EPSS flag")
	}
	validate, _, err := root.Find([]string{"validate"})
	if err != nil {
		t.Fatal(err)
	}
	if validate.Flags().Lookup("epss-filename") == nil {
		t.Fatal("validate lost --epss-filename")
	}

	dir := t.TempDir()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	args := []string{"download", "epss", "--epss-url", srv.URL + "/epss_scores-current.csv.gz", "--epss-cache-dir", dir}
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("download: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "CVE-2024-1234,0.42,0.84") {
		t.Fatalf("output %q", out.String())
	}
	out.Reset()
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("cached download: %v\n%s", err, out.String())
	}
	if gets.Load() != 1 {
		t.Fatalf("full file downloads = %d, want 1", gets.Load())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "epss_scores-2026-10-22.csv.gz" {
		t.Fatalf("cache entries %v", entries)
	}

	empty := t.TempDir()
	out.Reset()
	root.SetArgs([]string{"download", "epss", "--epss-url", srv.URL + "/epss_scores-current.csv.gz", "--epss-cache-dir", empty, "--epss-no-cache"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if gets.Load() != 3 {
		t.Fatalf("no-cache downloads = %d, want 3", gets.Load())
	}
	left, err := os.ReadDir(empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("--epss-no-cache wrote %v", left)
	}
}

type hostOnlyTransport struct {
	host string
	base http.RoundTripper
}

func (h hostOnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != h.host {
		return nil, fmt.Errorf("blocked request to %s", r.URL.Host)
	}
	return h.base.RoundTrip(r)
}

func gzipCSV(t *testing.T, plain string) []byte {
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

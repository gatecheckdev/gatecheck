package epss

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUserAgent(t *testing.T) {
	SetVersion("v1.2.3")
	got := userAgent()
	want := "gatecheck/v1.2.3 (+" + projectURL + ")"
	if got != want {
		t.Fatalf("user agent %q", got)
	}

	SetVersion("[Not Provided]")
	SetVersion("")
	SetVersion("unknown")
	if userAgent() != want {
		t.Fatalf("placeholder replaced version: %q", userAgent())
	}

	SetVersion("v9.9.9\r\nX-Bad: yes")
	got = userAgent()
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("user agent has a newline: %q", got)
	}
	if !strings.Contains(got, "gatecheck/v9.9.9") || !strings.Contains(got, projectURL) {
		t.Fatalf("user agent %q", got)
	}
}

func TestEPSSDateFromURL(t *testing.T) {
	cases := []struct {
		in   string
		date string
		ok   bool
	}{
		{"https://epss.example/epss_scores-2026-10-22.csv.gz", "2026-10-22", true},
		{"https://epss.example/mirror/epss_scores-2026-10-22.csv.gz", "2026-10-22", true},
		{"https://epss.example/epss_scores-current.csv.gz", "", false},
		{"https://epss.example/", "", false},
		{"https://epss.example/epss_scores-2026-10-22.csv.gz.evil", "", false},
		{"https://epss.example/epss_scores-2026-10-22.csv.gz/../../etc/passwd", "", false},
		{"://bad", "", false},
	}
	for _, tc := range cases {
		date, ok := epssDateFromURL(tc.in)
		if date != tc.date || ok != tc.ok {
			t.Errorf("%s got %q %v", tc.in, date, ok)
		}
	}
	name := epssCacheFilename("2026-10-22")
	if name != "epss_scores-2026-10-22.csv.gz" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		t.Fatal(name)
	}
}

func TestResolveCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "xdg"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("USERPROFILE", home)
	t.Setenv(envEPSSCache, "")
	t.Setenv(envEPSSCacheDir, "")

	dir, enabled := resolveCache(&FetchOptions{})
	if !enabled {
		t.Fatal("expected cache")
	}
	root, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "gatecheck", "epss")
	if dir != want {
		t.Fatalf("dir %s want %s", dir, want)
	}
	if !strings.HasPrefix(dir, home) {
		t.Fatalf("cache dir %s is outside %s", dir, home)
	}

	for _, v := range []string{"0", "false", "off", "no", "disabled", "disable", "none", " OFF "} {
		t.Setenv(envEPSSCache, v)
		if _, enabled = resolveCache(&FetchOptions{}); enabled {
			t.Fatalf("%q should disable the cache", v)
		}
	}

	t.Setenv(envEPSSCache, "on")
	custom := filepath.Join(home, "custom")
	t.Setenv(envEPSSCacheDir, custom)
	dir, enabled = resolveCache(&FetchOptions{})
	if !enabled || dir != custom {
		t.Fatalf("env dir: %s enabled=%v", dir, enabled)
	}

	t.Setenv(envEPSSCache, "off")
	dir, enabled = resolveCache(&FetchOptions{cacheDir: custom, cacheDirSet: true})
	if !enabled || dir != custom {
		t.Fatalf("flag dir should beat env off: %s enabled=%v", dir, enabled)
	}

	if _, enabled = resolveCache(&FetchOptions{cacheSet: true, cacheOn: false, cacheDir: custom, cacheDirSet: true}); enabled {
		t.Fatal("explicit off should win")
	}

	t.Setenv(envEPSSCacheDir, "")
	dir, enabled = resolveCache(&FetchOptions{cacheSet: true, cacheOn: true})
	if !enabled || dir != want {
		t.Fatalf("explicit on should beat env off: %s enabled=%v", dir, enabled)
	}

	t.Run("no home", func(t *testing.T) {
		t.Setenv("HOME", "")
		t.Setenv("XDG_CACHE_HOME", "")
		t.Setenv("LOCALAPPDATA", "")
		t.Setenv("USERPROFILE", "")
		t.Setenv(envEPSSCache, "")
		t.Setenv(envEPSSCacheDir, "")
		if _, err := os.UserCacheDir(); err != nil {
			if _, enabled := resolveCache(&FetchOptions{}); enabled {
				t.Fatal("expected cache to stay off when there is no user cache dir")
			}
		}
	})
}

func TestDownloadDataCaching(t *testing.T) {
	SetVersion("v1.2.3-test")
	f := newEPSSFixture(t)

	t.Run("reuse current file", func(t *testing.T) {
		f.begin("2026-10-22")
		dir := t.TempDir()
		var buf bytes.Buffer
		opts := []Option{WithURL(f.srv.URL), WithClient(f.client), WithCacheDir(dir)}
		if err := DownloadData(&buf, opts...); err != nil {
			t.Fatal(err)
		}
		if buf.String() != csvFor("2026-10-22") {
			t.Fatalf("csv %q hits %s", buf.String(), f.dump())
		}
		if f.fileGets() != 1 {
			t.Fatalf("gets %d hits %s", f.fileGets(), f.dump())
		}

		f.setFail(true)
		data := &Data{}
		if err := FetchData(data, opts...); err != nil {
			t.Fatal(err)
		}
		if data.CVEs["CVE-2024-1234"].EPSS != "0.42" || data.ModelVersion != dataModel {
			t.Fatalf("parsed %#v", data)
		}
		if f.fileGets() != 1 {
			t.Fatalf("cached run downloaded again: %d hits %s", f.fileGets(), f.dump())
		}
		assertCacheFiles(t, dir, "epss_scores-2026-10-22.csv.gz")
		if bad := f.badUserAgent(); bad != "" {
			t.Fatal(bad)
		}
	})

	t.Run("current alias", func(t *testing.T) {
		f.begin("2026-10-22")
		dir := t.TempDir()
		var buf bytes.Buffer
		if err := DownloadData(&buf, WithURL(f.srv.URL+"/epss_scores-current.csv.gz"), WithClient(f.client), WithCacheDir(dir)); err != nil {
			t.Fatal(err)
		}
		if buf.String() != csvFor("2026-10-22") {
			t.Fatalf("csv %q hits %s", buf.String(), f.dump())
		}
		if err := DownloadData(io.Discard, WithURL(f.srv.URL+"/epss_scores-current.csv.gz"), WithClient(f.client), WithCacheDir(dir)); err != nil {
			t.Fatal(err)
		}
		if f.fileGets() != 1 {
			t.Fatalf("gets %d hits %s", f.fileGets(), f.dump())
		}
	})

	t.Run("new date", func(t *testing.T) {
		f.begin("2026-10-22")
		dir := t.TempDir()
		opts := []Option{WithURL(f.srv.URL), WithClient(f.client), WithCacheDir(dir)}
		if err := DownloadData(io.Discard, opts...); err != nil {
			t.Fatal(err)
		}
		f.setDate("2026-10-23")
		var buf bytes.Buffer
		if err := DownloadData(&buf, opts...); err != nil {
			t.Fatal(err)
		}
		if buf.String() != csvFor("2026-10-23") {
			t.Fatalf("csv %q hits %s", buf.String(), f.dump())
		}
		if f.fileGets() != 2 {
			t.Fatalf("gets %d hits %s", f.fileGets(), f.dump())
		}
		assertCacheFiles(t, dir, "epss_scores-2026-10-22.csv.gz", "epss_scores-2026-10-23.csv.gz")
	})

	t.Run("corrupt cache", func(t *testing.T) {
		f.begin("2026-10-22")
		dir := t.TempDir()
		opts := []Option{WithURL(f.srv.URL), WithClient(f.client), WithCacheDir(dir)}
		if err := DownloadData(io.Discard, opts...); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "epss_scores-2026-10-22.csv.gz")
		if err := os.WriteFile(path, []byte("not gzip"), 0o644); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := DownloadData(&buf, opts...); err != nil {
			t.Fatal(err)
		}
		if buf.String() != csvFor("2026-10-22") {
			t.Fatalf("csv %q", buf.String())
		}
		if f.fileGets() != 2 {
			t.Fatalf("gets %d", f.fileGets())
		}
		cached, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(cached, []byte{0x1f, 0x8b}) {
			t.Fatal("cache was not replaced with gzip")
		}
	})

	t.Run("dated url", func(t *testing.T) {
		f.begin("2026-10-22")
		dir := t.TempDir()
		raw := f.srv.URL + "/mirror/epss_scores-2026-10-22.csv.gz"
		opts := []Option{WithURL(raw), WithClient(f.client), WithCacheDir(dir)}
		if err := DownloadData(io.Discard, opts...); err != nil {
			t.Fatal(err)
		}
		f.setFail(true)
		var buf bytes.Buffer
		if err := DownloadData(&buf, opts...); err != nil {
			t.Fatal(err)
		}
		if buf.String() != csvFor("2026-10-22") {
			t.Fatalf("csv %q hits %s", buf.String(), f.dump())
		}
		if f.fileGets() != 1 || f.heads() != 0 {
			t.Fatalf("gets %d heads %d hits %s", f.fileGets(), f.heads(), f.dump())
		}
	})

	t.Run("cache disabled", func(t *testing.T) {
		f.begin("2026-10-22")
		dir := t.TempDir()
		opts := []Option{WithURL(f.srv.URL), WithClient(f.client), WithCache(false), WithCacheDir(dir)}
		if err := DownloadData(io.Discard, opts...); err != nil {
			t.Fatal(err)
		}
		if err := DownloadData(io.Discard, opts...); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("wrote cache while disabled: %v", entries)
		}
		if f.fileGets() != 2 {
			t.Fatalf("gets %d hits %s", f.fileGets(), f.dump())
		}
	})

	t.Run("env cache dir", func(t *testing.T) {
		f.begin("2026-10-22")
		dir := t.TempDir()
		t.Setenv(envEPSSCache, "")
		t.Setenv(envEPSSCacheDir, dir)
		if err := DownloadData(io.Discard, WithURL(f.srv.URL), WithClient(f.client)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "epss_scores-2026-10-22.csv.gz")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("env off", func(t *testing.T) {
		f.begin("2026-10-22")
		dir := t.TempDir()
		t.Setenv(envEPSSCache, "off")
		t.Setenv(envEPSSCacheDir, dir)
		opts := []Option{WithURL(f.srv.URL), WithClient(f.client)}
		if err := DownloadData(io.Discard, opts...); err != nil {
			t.Fatal(err)
		}
		if err := DownloadData(io.Discard, opts...); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("wrote cache while disabled: %v", entries)
		}
		if f.fileGets() != 2 {
			t.Fatalf("gets %d hits %s", f.fileGets(), f.dump())
		}
	})
}

func TestDownloadDataBadStatus(t *testing.T) {
	SetVersion("v1.2.3-test")
	var sawUA atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if strings.HasPrefix(ua, "gatecheck/") && strings.Contains(ua, projectURL) && !strings.Contains(ua, "Go-http-client") {
			sawUA.Store(true)
		}
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Timeout = 5 * time.Second
	dir := t.TempDir()
	err := DownloadData(io.Discard, WithURL(srv.URL), WithClient(client), WithCacheDir(dir))
	if err == nil {
		t.Fatal("expected an error")
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("cached a failed download: %v", entries)
	}
	if !sawUA.Load() {
		t.Fatal("request did not identify gatecheck")
	}
}

type requestHit struct {
	method string
	path   string
}

type epssFixture struct {
	srv     *httptest.Server
	client  *http.Client
	payload map[string][]byte

	mu      sync.Mutex
	date    string
	failGET bool
	hits    []requestHit
	badUA   string
}

func newEPSSFixture(t *testing.T) *epssFixture {
	t.Helper()
	f := &epssFixture{
		date: "2026-10-22",
		payload: map[string][]byte{
			"2026-10-22": gzipBytes(t, csvFor("2026-10-22")),
			"2026-10-23": gzipBytes(t, csvFor("2026-10-23")),
		},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	f.client = f.srv.Client()
	f.client.Timeout = 5 * time.Second
	return f
}

func (f *epssFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits = append(f.hits, requestHit{method: r.Method, path: r.URL.Path})
	ua := r.Header.Get("User-Agent")
	if !strings.HasPrefix(ua, "gatecheck/") || !strings.Contains(ua, projectURL) || strings.Contains(ua, "Go-http-client") {
		f.badUA = ua
	}
	date := f.date
	failGET := f.failGET
	f.mu.Unlock()

	if fileDate, ok := epssDateFromURL("https://epss.example" + r.URL.Path); ok {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if failGET {
			http.Error(w, "fail", http.StatusInternalServerError)
			return
		}
		payload := f.payload[fileDate]
		if payload == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(payload)
		return
	}

	switch r.URL.Path {
	case "/", "":
		w.Header().Set("Location", "/mirror/")
		w.WriteHeader(http.StatusMovedPermanently)
	case "/mirror", "/mirror/":
		w.Header().Set("Location", "epss_scores-"+date+".csv.gz")
		w.WriteHeader(http.StatusFound)
	case "/epss_scores-current.csv.gz":
		w.Header().Set("Location", "epss_scores-"+date+".csv.gz")
		w.WriteHeader(http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

func (f *epssFixture) begin(date string) {
	f.mu.Lock()
	f.date = date
	f.failGET = false
	f.hits = nil
	f.badUA = ""
	f.mu.Unlock()
}

func (f *epssFixture) setDate(date string) {
	f.mu.Lock()
	f.date = date
	f.mu.Unlock()
}

func (f *epssFixture) setFail(fail bool) {
	f.mu.Lock()
	f.failGET = fail
	f.mu.Unlock()
}

func (f *epssFixture) fileGets() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, hit := range f.hits {
		if hit.method == http.MethodGet && datedEPSSPattern.MatchString(hit.path) {
			n++
		}
	}
	return n
}

func (f *epssFixture) heads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, hit := range f.hits {
		if hit.method == http.MethodHead {
			n++
		}
	}
	return n
}

func (f *epssFixture) badUserAgent() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.badUA
}

func (f *epssFixture) dump() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprint(f.hits)
}

func csvFor(date string) string {
	return "#model_version:" + dataModel + ",score_date:" + date + "T00:00:00Z\ncve,epss,percentile\nCVE-2024-1234,0.42,0.84\n"
}

func gzipBytes(t *testing.T, plain string) []byte {
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

func assertCacheFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(names) {
		t.Fatalf("cache files %v want %v", entries, names)
	}
	got := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || strings.Contains(entry.Name(), "..") {
			t.Fatalf("unexpected cache entry %s", entry.Name())
		}
		got[entry.Name()] = true
	}
	for _, name := range names {
		if !got[name] {
			t.Fatalf("missing %s in %v", name, got)
		}
	}
}

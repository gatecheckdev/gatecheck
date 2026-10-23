package bootstrap

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gatecheckdev/gatecheck/internal/fetch"
)

func TestInstallGrypeChecksumAndIdempotent(t *testing.T) {
	archiveBody := tarGz(t, map[string]string{
		"README.md": "readme",
		"grype":     "grype-binary",
	})
	asset, err := grypeAsset(GrypeVersion, Platform{GOOS: "linux", GOARCH: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	sum := sha256.Sum256(archiveBody)
	good := hex.EncodeToString(sum[:])
	mode := "good"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "gatecheck/") {
			http.Error(w, "bad ua", http.StatusBadRequest)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, asset.Checksum):
			digest := good
			if mode == "bad" {
				digest = strings.Repeat("ab", 32)
			}
			if mode == "missing" {
				digest = good
				fmt.Fprintf(w, "%s  other.tar.gz\n", digest)
				return
			}
			fmt.Fprintf(w, "%s  %s\n", digest, asset.Asset)
		case strings.HasSuffix(r.URL.Path, asset.Asset):
			_, _ = w.Write(archiveBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	home := t.TempDir()
	opts := Options{
		Home:       home,
		ToolsCSV:   "grype",
		Client:     srv.Client(),
		GitHubBase: srv.URL,
		UserAgent:  "gatecheck/test (+https://github.com/gatecheckdev/gatecheck)",
		Platform:   Platform{GOOS: "linux", GOARCH: "amd64"},
	}
	var out, errb bytes.Buffer
	opts.Stdout = &out
	opts.Stderr = &errb
	if err := Bootstrap(context.Background(), opts); err != nil {
		t.Fatalf("install: %v\n%s", err, errb.String())
	}
	if hits.Load() != 2 {
		t.Fatalf("requests = %d, want 2", hits.Load())
	}
	dest := filepath.Join(home, "bin", "grype")
	body, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "grype-binary" {
		t.Fatalf("binary %q", body)
	}
	if !strings.Contains(out.String(), "installed grype "+GrypeVersion+" "+dest) {
		t.Fatalf("stdout %q", out.String())
	}
	readme := filepath.Join(home, "bin", "README.md")
	if _, err := os.Stat(readme); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("archive readme was installed")
	}

	out.Reset()
	if err := Bootstrap(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("second install requests = %d, want 2", hits.Load())
	}
	if !strings.Contains(out.String(), "grype "+GrypeVersion+" already installed") {
		t.Fatalf("stdout %q", out.String())
	}

	opts.Force = true
	if err := Bootstrap(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 4 {
		t.Fatalf("force requests = %d, want 4", hits.Load())
	}

	mode = "bad"
	opts.Force = true
	badHome := t.TempDir()
	opts.Home = badHome
	err = Bootstrap(context.Background(), opts)
	if !errors.Is(err, fetch.ErrChecksumMismatch) {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(badHome, "bin", "grype")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("checksum mismatch left a binary")
	}
	assertNoTemps(t, filepath.Join(badHome, "bin"))

	mode = "missing"
	err = Bootstrap(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "no entry") {
		t.Fatalf("missing checksum entry: %v", err)
	}
}

func TestInstallZipBinary(t *testing.T) {
	body := zipBytes(t, map[string]string{
		"nested/not-grype": "nope",
		"grype.exe":        "from-zip",
	})
	asset, err := grypeAsset(GrypeVersion, Platform{GOOS: "windows", GOARCH: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, asset.Checksum):
			fmt.Fprintf(w, "%x  %s\n", sum, asset.Asset)
		case strings.HasSuffix(r.URL.Path, asset.Asset):
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	home := t.TempDir()
	var out bytes.Buffer
	err = Bootstrap(context.Background(), Options{
		Home:       home,
		ToolsCSV:   "grype",
		Client:     srv.Client(),
		GitHubBase: srv.URL,
		Platform:   Platform{GOOS: "windows", GOARCH: "amd64"},
		Stdout:     &out,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(home, "bin", "grype.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from-zip" {
		t.Fatalf("zip binary %q", got)
	}
}

func TestSemgrepWheelInstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix osemgrep install uses a symlink")
	}
	core := "semgrep-core-bytes"
	lib := "lib-bytes"
	wheelBody := zipBytes(t, map[string]string{
		"semgrep-" + SemgrepVersion + ".data/purelib/semgrep/bin/__init__.py":     "skip-me",
		"semgrep-" + SemgrepVersion + ".data/purelib/semgrep/bin/semgrep-core":    core,
		"semgrep-" + SemgrepVersion + ".data/purelib/semgrep/bin/libs/libdemo.so": lib,
	})
	sum := sha256.Sum256(wheelBody)
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/pypi/semgrep/" + SemgrepVersion + "/json":
			if err := json.NewEncoder(w).Encode(map[string]any{
				"urls": semgrepWheelEntries(srv.URL+"/wheels/semgrep.whl", hex.EncodeToString(sum[:])),
			}); err != nil {
				t.Errorf("encode json: %v", err)
			}
		case "/wheels/semgrep.whl":
			_, _ = w.Write(wheelBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	home := t.TempDir()
	opts := Options{
		Home:      home,
		ToolsCSV:  "semgrep",
		Client:    srv.Client(),
		PyPIBase:  srv.URL,
		Platform:  Platform{GOOS: "linux", GOARCH: "amd64", Libc: "glibc"},
		UserAgent: "gatecheck/test (+https://github.com/gatecheckdev/gatecheck)",
	}
	var out, errb bytes.Buffer
	opts.Stdout = &out
	opts.Stderr = &errb
	if err := Bootstrap(context.Background(), opts); err != nil {
		t.Fatalf("install: %v stderr=%s", err, errb.String())
	}
	if hits.Load() != 2 {
		t.Fatalf("requests = %d", hits.Load())
	}
	link := filepath.Join(home, "bin", "osemgrep")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if target != "semgrep-core" {
		t.Fatalf("symlink %s", target)
	}
	got, err := os.ReadFile(filepath.Join(home, "bin", "semgrep-core"))
	if err != nil || string(got) != core {
		t.Fatalf("core %q %v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(home, "bin", "libs", "libdemo.so"))
	if err != nil || string(got) != lib {
		t.Fatalf("lib %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(home, "bin", "__init__.py")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("python file was installed")
	}
	if !strings.Contains(out.String(), "installed semgrep "+SemgrepVersion+" "+link) {
		t.Fatalf("stdout %q", out.String())
	}

	out.Reset()
	if err := Bootstrap(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("idempotent requests = %d", hits.Load())
	}
	if !strings.Contains(out.String(), "already installed") {
		t.Fatalf("stdout %q", out.String())
	}

	badHome := t.TempDir()
	opts.Home = badHome
	opts.Force = true
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/semgrep/" + SemgrepVersion + "/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"urls": semgrepWheelEntries(srv.URL+"/wheels/semgrep.whl", strings.Repeat("0", 64)),
			})
		case "/wheels/semgrep.whl":
			_, _ = w.Write(wheelBody)
		default:
			http.NotFound(w, r)
		}
	})
	err = Bootstrap(context.Background(), opts)
	if !errors.Is(err, fetch.ErrChecksumMismatch) {
		t.Fatalf("mismatch %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(badHome, "bin", "osemgrep")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("mismatch installed osemgrep")
	}
	assertNoTemps(t, badHome)
}

func TestSemgrepWindowsCopy(t *testing.T) {
	wheelBody := zipBytes(t, map[string]string{
		"semgrep/bin/semgrep-core": "win-core",
	})
	sum := sha256.Sum256(wheelBody)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/semgrep/" + SemgrepVersion + "/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"urls": semgrepWheelEntries(srv.URL+"/semgrep.whl", hex.EncodeToString(sum[:])),
			})
		case "/semgrep.whl":
			_, _ = w.Write(wheelBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	home := t.TempDir()
	err := Bootstrap(context.Background(), Options{
		Home:     home,
		ToolsCSV: "osemgrep",
		Client:   srv.Client(),
		PyPIBase: srv.URL,
		Platform: Platform{GOOS: "windows", GOARCH: "amd64"},
		Stdout:   ioDiscard(),
		Stderr:   ioDiscard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(home, "bin", "osemgrep.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "win-core" {
		t.Fatalf("copy %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, "bin", "osemgrep")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("windows install created a unix symlink name")
	}
}

func TestSemgrepSkip(t *testing.T) {
	client := &http.Client{Transport: denyTransport{t: t}}
	var errb bytes.Buffer
	err := Bootstrap(context.Background(), Options{
		Home:     t.TempDir(),
		ToolsCSV: "semgrep",
		Client:   client,
		Platform: Platform{GOOS: "linux", GOARCH: "ppc64le", Libc: "glibc"},
		Stdout:   ioDiscard(),
		Stderr:   &errb,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errb.String(), "no PyPI wheel") {
		t.Fatalf("stderr %q", errb.String())
	}

	wheelBody := zipBytes(t, map[string]string{"semgrep/bin/README": "no binary"})
	sum := sha256.Sum256(wheelBody)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/semgrep/" + SemgrepVersion + "/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"urls": []map[string]any{{
					"filename":    "semgrep-manylinux_2_34_x86_64.whl",
					"url":         srv.URL + "/semgrep.whl",
					"packagetype": "bdist_wheel",
					"digests":     map[string]string{"sha256": hex.EncodeToString(sum[:])},
				}},
			})
		case "/semgrep.whl":
			_, _ = w.Write(wheelBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	errb.Reset()
	err = Bootstrap(context.Background(), Options{
		Home:     t.TempDir(),
		ToolsCSV: "semgrep",
		Client:   srv.Client(),
		PyPIBase: srv.URL,
		Platform: Platform{GOOS: "linux", GOARCH: "amd64", Libc: "glibc"},
		Stdout:   ioDiscard(),
		Stderr:   &errb,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errb.String(), "does not contain semgrep-core") {
		t.Fatalf("stderr %q", errb.String())
	}
}

func TestUnsupportedGrypeAndUnknownTool(t *testing.T) {
	client := &http.Client{Transport: denyTransport{t: t}}
	err := Bootstrap(context.Background(), Options{
		Home:     t.TempDir(),
		ToolsCSV: "grype",
		Client:   client,
		Platform: Platform{GOOS: "windows", GOARCH: "arm64"},
		Stdout:   ioDiscard(),
		Stderr:   ioDiscard(),
	})
	if err == nil || !strings.Contains(err.Error(), "no published release asset") {
		t.Fatalf("error %v", err)
	}
	if err := Bootstrap(context.Background(), Options{Home: t.TempDir(), ToolsCSV: "trivy", Stdout: ioDiscard(), Stderr: ioDiscard()}); err == nil {
		t.Fatal("expected unknown tool error")
	}
}

func TestListInstalled(t *testing.T) {
	home := t.TempDir()
	var buf bytes.Buffer
	if err := Bootstrap(context.Background(), Options{Home: home, List: true, Stdout: &buf}); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	if !strings.HasPrefix(text, "TOOL       PINNED     INSTALLED  PATH\n") {
		t.Fatalf("header %q", text)
	}
	for _, version := range []string{GrypeVersion, SyftVersion, GitleaksVersion, SemgrepVersion} {
		if !strings.Contains(text, version) {
			t.Fatalf("missing %s in %s", version, text)
		}
	}
	if strings.Count(text, "\n") != 5 {
		t.Fatalf("lines %q", text)
	}
}

func TestUnsafeLibPath(t *testing.T) {
	rel, ok := semgrepLibRel("semgrep/bin/libs/../../escaped.so")
	if !ok {
		t.Fatal("expected a libs relative path")
	}
	if _, err := safeJoin(t.TempDir(), rel); err == nil {
		t.Fatal("expected unsafe path error")
	}
	got, err := safeJoin(t.TempDir(), "libdemo.so")
	if err != nil || !strings.HasSuffix(got, "libdemo.so") {
		t.Fatalf("safe path %s %v", got, err)
	}
}

type denyTransport struct {
	t *testing.T
}

func (d denyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	d.t.Errorf("unexpected request %s", r.URL)
	return nil, errors.New("unexpected request")
}

func semgrepWheelEntries(wheelURL, sum string) []map[string]any {
	names := []string{
		"semgrep-manylinux_2_34_x86_64.whl",
		"semgrep-manylinux_2_34_aarch64.whl",
		"semgrep-musllinux_1_2_x86_64.whl",
		"semgrep-musllinux_1_2_aarch64.whl",
		"semgrep-macosx_10_14_x86_64.whl",
		"semgrep-macosx_11_0_arm64.whl",
		"semgrep-win_amd64.whl",
	}
	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		out = append(out, map[string]any{
			"filename":    name,
			"url":         wheelURL,
			"packagetype": "bdist_wheel",
			"digests":     map[string]string{"sha256": sum},
		})
	}
	return out
}

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".fetch-") || strings.HasPrefix(name, ".partial-") || strings.HasPrefix(name, ".semgrep-staging") || strings.HasPrefix(name, ".download-") {
			t.Fatalf("leftover %s", name)
		}
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func ioDiscard() discard { return discard{} }

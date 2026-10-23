package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/epss"
)

func TestInstallReplacesResolvedBinary(t *testing.T) {
	goos, goarch := runtime.GOOS, runtime.GOARCH
	if !supportedPlatform(goos, goarch) {
		t.Skip("no release asset for this process")
	}
	exe, _ := tempBinary(t, "old")
	_, files := releaseFiles(t, "v0.9.0", goos, goarch, "new-binary", "archive")
	gh := startGitHub(t, "v0.9.0", files)
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "0.8.0", exe, goos, goarch)
	if err := Run(context.Background(), opt); err != nil {
		t.Fatalf("update: %v\n%s", err, ioBuf.err.String())
	}
	installed, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(installed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-binary" {
		t.Fatalf("binary %q", got)
	}
	if exe != installed {
		info, err := os.Lstat(exe)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Fatal("install path is no longer a symlink")
		}
	}
	if !strings.Contains(ioBuf.out.String(), "Updated "+installed+" to v0.9.0") {
		t.Fatalf("stdout %q", ioBuf.out.String())
	}
	if gh.downloads() == 0 {
		t.Fatal("archive was not downloaded")
	}
}

func TestInstallWindowsArchive(t *testing.T) {
	exe := writeBinary(t, filepath.Join(t.TempDir(), "gatecheck.exe"), "old")
	_, files := releaseFiles(t, "v0.9.0", "windows", "amd64", "win-binary", "archive")
	gh := startGitHub(t, "v0.9.0", files)
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "0.8.0", exe, "windows", "amd64")
	if err := Run(context.Background(), opt); err != nil {
		t.Fatalf("update: %v\n%s", err, ioBuf.err.String())
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "win-binary" {
		t.Fatalf("binary %q", got)
	}
}

func TestChecksumMismatchRejected(t *testing.T) {
	assertRejected(t, "wrong", "mismatch")
}

func TestChecksumOfArchiveNotBinary(t *testing.T) {
	assertRejected(t, "binary", "mismatch")
}

func TestMissingChecksumRejected(t *testing.T) {
	assertRejected(t, "missing", "missing")
}

func TestInvalidChecksumRejected(t *testing.T) {
	assertRejected(t, "invalid", "invalid")
}

func assertRejected(t *testing.T, mode, want string) {
	t.Helper()
	exe := writeBinary(t, filepath.Join(t.TempDir(), "gatecheck"), "old")
	name, files := releaseFiles(t, "v0.9.0", "linux", "amd64", "new-binary", mode)
	gh := startGitHub(t, "v0.9.0", files)
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "0.8.0", exe, "linux", "amd64")
	err := Run(context.Background(), opt)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error %v", err)
	}
	got, readErr := os.ReadFile(exe)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "old" {
		t.Fatalf("binary changed to %q", got)
	}
	if mode == "missing" || mode == "invalid" {
		if gh.count("download:"+name) != 0 {
			t.Fatalf("archive downloaded despite %s checksum", mode)
		}
	}
	if strings.Contains(ioBuf.out.String(), "Updated") {
		t.Fatalf("stdout %q", ioBuf.out.String())
	}
}

func TestCheckDoesNotDownload(t *testing.T) {
	_, files := releaseFiles(t, "v0.9.0", "linux", "amd64", "new-binary", "archive")
	gh := startGitHub(t, "v0.9.0", files)
	exe := writeBinary(t, filepath.Join(t.TempDir(), "gatecheck"), "old")
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "v0.8.0", exe, "linux", "amd64")
	opt.CheckOnly = true
	opt.AssumeYes = false
	if err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if ioBuf.out.String() != "current v0.8.0\nlatest v0.9.0\n" {
		t.Fatalf("stdout %q", ioBuf.out.String())
	}
	if gh.downloads() != 0 {
		t.Fatalf("downloads %d", gh.downloads())
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatal("binary changed")
	}
}

func TestCheckPinnedRelease(t *testing.T) {
	gh := startGitHub(t, "v1.2.3", map[string][]byte{})
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "0.8.0", "", "linux", "amd64")
	opt.CheckOnly = true
	opt.TargetVersion = "v1.2.3"
	if err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if ioBuf.out.String() != "current v0.8.0\ntarget v1.2.3\n" {
		t.Fatalf("stdout %q", ioBuf.out.String())
	}
	if gh.count("latest") != 0 || gh.count("tag") != 1 {
		t.Fatalf("hits %#v", gh.snapshot())
	}
}

func TestUpToDateSkipsDownload(t *testing.T) {
	gh := startGitHub(t, "v0.9.0", map[string][]byte{})
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "0.9.0", "", "linux", "amd64")
	if err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if ioBuf.out.String() != "gatecheck v0.9.0 is up to date\n" {
		t.Fatalf("stdout %q", ioBuf.out.String())
	}
	if gh.downloads() != 0 {
		t.Fatal("downloaded")
	}
}

func TestNewerThanLatest(t *testing.T) {
	gh := startGitHub(t, "v0.9.0", map[string][]byte{})
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "v1.0.0", "", "linux", "amd64")
	if err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if ioBuf.out.String() != "gatecheck v1.0.0 is newer than the latest release v0.9.0\n" {
		t.Fatalf("stdout %q", ioBuf.out.String())
	}
}

func TestDevBuildRefuses(t *testing.T) {
	for _, current := range []string{"", "dev", "DEV", "[Not Provided]", "unknown", "not-a-version"} {
		t.Run(current, func(t *testing.T) {
			gh := startGitHub(t, "v0.9.0", map[string][]byte{})
			var ioBuf cliIO
			opt := ioBuf.options(gh.URL(), current, "", "linux", "amd64")
			err := Run(context.Background(), opt)
			if err == nil || !strings.Contains(err.Error(), "--version") {
				t.Fatalf("error %v", err)
			}
			if gh.count("latest")+gh.count("tag")+gh.downloads() != 0 {
				t.Fatalf("network %#v", gh.snapshot())
			}
		})
	}
}

func TestDevBuildInstallsPinnedRelease(t *testing.T) {
	exe := writeBinary(t, filepath.Join(t.TempDir(), "gatecheck"), "old")
	_, files := releaseFiles(t, "v0.9.0", "linux", "amd64", "pinned", "archive")
	gh := startGitHub(t, "v0.9.0", files)
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "dev", exe, "linux", "amd64")
	opt.TargetVersion = "v0.9.0"
	if err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "pinned" {
		t.Fatalf("binary %q", got)
	}
	if gh.count("latest") != 0 {
		t.Fatal("requested latest")
	}
}

func TestNonTerminalRequiresYes(t *testing.T) {
	exe := writeBinary(t, filepath.Join(t.TempDir(), "gatecheck"), "old")
	_, files := releaseFiles(t, "v0.9.0", "linux", "amd64", "new-binary", "archive")
	gh := startGitHub(t, "v0.9.0", files)
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "0.8.0", exe, "linux", "amd64")
	opt.AssumeYes = false
	err := Run(context.Background(), opt)
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error %v", err)
	}
	if gh.downloads() != 0 {
		t.Fatal("downloaded")
	}
	got, readErr := os.ReadFile(exe)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "old" {
		t.Fatal("binary changed")
	}
}

func TestPromptDecline(t *testing.T) {
	exe := writeBinary(t, filepath.Join(t.TempDir(), "gatecheck"), "old")
	_, files := releaseFiles(t, "v0.9.0", "linux", "amd64", "new-binary", "archive")
	gh := startGitHub(t, "v0.9.0", files)
	var ioBuf cliIO
	ioBuf.in.WriteString("n\n")
	opt := ioBuf.options(gh.URL(), "0.8.0", exe, "linux", "amd64")
	opt.AssumeYes = false
	opt.IsTerminal = func(io.Reader) bool { return true }
	if err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ioBuf.err.String(), "update cancelled") {
		t.Fatalf("stderr %q", ioBuf.err.String())
	}
	if gh.downloads() != 0 {
		t.Fatal("downloaded")
	}
}

func TestPromptAccept(t *testing.T) {
	exe := writeBinary(t, filepath.Join(t.TempDir(), "gatecheck"), "old")
	_, files := releaseFiles(t, "v0.9.0", "linux", "amd64", "yes-binary", "archive")
	gh := startGitHub(t, "v0.9.0", files)
	var ioBuf cliIO
	ioBuf.in.WriteString("yes\n")
	opt := ioBuf.options(gh.URL(), "0.8.0", exe, "linux", "amd64")
	opt.AssumeYes = false
	opt.IsTerminal = func(io.Reader) bool { return true }
	if err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "yes-binary" {
		t.Fatalf("binary %q", got)
	}
	if !strings.Contains(ioBuf.err.String(), "Update gatecheck from v0.8.0 to v0.9.0?") {
		t.Fatalf("stderr %q", ioBuf.err.String())
	}
}

func TestUnsupportedPlatform(t *testing.T) {
	exe := writeBinary(t, filepath.Join(t.TempDir(), "gatecheck"), "old")
	gh := startGitHub(t, "v0.9.0", map[string][]byte{})
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "0.8.0", exe, "linux", "arm")
	err := Run(context.Background(), opt)
	if err == nil || !strings.Contains(err.Error(), "linux/arm") {
		t.Fatalf("error %v", err)
	}
	if gh.downloads() != 0 {
		t.Fatal("downloaded")
	}
}

func TestDowngradeWithYes(t *testing.T) {
	exe := writeBinary(t, filepath.Join(t.TempDir(), "gatecheck"), "old")
	_, files := releaseFiles(t, "v0.8.0", "linux", "amd64", "older", "archive")
	gh := startGitHub(t, "v0.8.0", files)
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "0.9.0", exe, "linux", "amd64")
	opt.TargetVersion = "0.8.0"
	if err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "older" {
		t.Fatalf("binary %q", got)
	}
	if gh.count("latest") != 0 || gh.count("tag") != 1 {
		t.Fatalf("hits %#v", gh.snapshot())
	}
}

func TestUpdateReportsUnwritableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory mode bits do not block this user")
	}
	dir := t.TempDir()
	exe := writeBinary(t, filepath.Join(dir, "gatecheck"), "old")
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	_, files := releaseFiles(t, "v0.9.0", "linux", "amd64", "new-binary", "archive")
	gh := startGitHub(t, "v0.9.0", files)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "0.8.0", exe, "linux", "amd64")
	err := Run(context.Background(), opt)
	if err == nil || !strings.Contains(err.Error(), "sudo") || !strings.Contains(err.Error(), "reinstall") {
		t.Fatalf("error %v", err)
	}
	if gh.downloads() != 0 {
		t.Fatal("downloaded")
	}
}

func TestRejectsOffHostRedirect(t *testing.T) {
	exe := writeBinary(t, filepath.Join(t.TempDir(), "gatecheck"), "old")
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != epss.UserAgent() {
			http.Error(w, "ua", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/repos/gatecheckdev/gatecheck/releases/latest":
			name, err := assetName("v0.9.0", "linux", "amd64")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = fmt.Fprintf(w, `{"tag_name":"v0.9.0","assets":[{"name":%q,"browser_download_url":%q},{"name":"checksums.txt","browser_download_url":%q}]}`,
				name, srv.URL+"/download/"+name, srv.URL+"/download/checksums.txt")
		case "/download/checksums.txt":
			w.Header().Set("Location", "http://example.test/checksums.txt")
			w.WriteHeader(http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	var ioBuf cliIO
	opt := ioBuf.options(srv.URL, "0.8.0", exe, "linux", "amd64")
	err := Run(context.Background(), opt)
	if err == nil || !strings.Contains(err.Error(), "example.test") {
		t.Fatalf("error %v", err)
	}
	got, readErr := os.ReadFile(exe)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "old" {
		t.Fatal("binary changed")
	}
}

func TestGitHubTokenOnDownload(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "test-token")
	exe := writeBinary(t, filepath.Join(t.TempDir(), "gatecheck"), "old")
	_, files := releaseFiles(t, "v0.9.0", "linux", "amd64", "token-binary", "archive")
	gh := startGitHub(t, "v0.9.0", files)
	var ioBuf cliIO
	opt := ioBuf.options(gh.URL(), "0.8.0", exe, "linux", "amd64")
	if err := Run(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "token-binary" {
		t.Fatalf("binary %q", got)
	}
}

func TestRateLimitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	var ioBuf cliIO
	opt := ioBuf.options(srv.URL, "0.8.0", "", "linux", "amd64")
	err := Run(context.Background(), opt)
	if err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("error %v", err)
	}
}

func TestReleaseNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	var ioBuf cliIO
	opt := ioBuf.options(srv.URL, "0.8.0", "", "linux", "amd64")
	opt.TargetVersion = "v9.9.9"
	err := Run(context.Background(), opt)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error %v", err)
	}
}

func TestInvalidTargetVersion(t *testing.T) {
	var ioBuf cliIO
	opt := ioBuf.options("http://127.0.0.1:1", "0.8.0", "", "linux", "amd64")
	opt.TargetVersion = "latest"
	err := Run(context.Background(), opt)
	if err == nil || !strings.Contains(err.Error(), "vX.Y.Z") {
		t.Fatalf("error %v", err)
	}
}

func TestExtractNestedBinary(t *testing.T) {
	archive := tarGZ(t, map[string]string{"gatecheck_0.9.0_linux_amd64/gatecheck": "nested"})
	got, err := extractBinary(archive, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "nested" {
		t.Fatalf("binary %q", got)
	}
}

func TestExtractRejectsUnsafePath(t *testing.T) {
	archive := tarGZ(t, map[string]string{"../gatecheck": "pwn"})
	if _, err := extractBinary(archive, "linux"); err == nil {
		t.Fatal("expected unsafe path error")
	}
}

func TestExtractIgnoresSymlink(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	hdr := &tar.Header{Name: "gatecheck", Typeflag: tar.TypeSymlink, Linkname: "/tmp/other", Mode: 0o777}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := extractBinary(buf.Bytes(), "linux")
	if err == nil || !strings.Contains(err.Error(), "does not contain") {
		t.Fatalf("error %v", err)
	}
}

func TestDefaultClientHonorsProxy(t *testing.T) {
	if os.Getenv("GATECHECK_UPDATE_PROXY_CHILD") == "1" {
		if err := proxyChildRequest(); err != nil {
			t.Fatal(err)
		}
		return
	}

	ip := firstRoutableIPv4(t)
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skip(err)
	}
	var direct atomic.Bool
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct.Store(true)
		http.Error(w, "direct", http.StatusInternalServerError)
	}))
	target.Listener = listener
	target.Start()
	t.Cleanup(target.Close)

	var proxied atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Store(true)
		_, _ = io.WriteString(w, "proxied")
	}))
	t.Cleanup(proxy.Close)

	cmd := exec.Command(os.Args[0], "-test.run=^TestDefaultClientHonorsProxy$", "-test.count=1")
	cmd.Env = proxyChildEnv(
		"GATECHECK_UPDATE_PROXY_CHILD=1",
		"GATECHECK_UPDATE_TARGET="+target.URL,
		"HTTP_PROXY="+proxy.URL,
		"http_proxy="+proxy.URL,
		"HTTPS_PROXY="+proxy.URL,
		"https_proxy="+proxy.URL,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("proxy child: %v\n%s", err, out)
	}
	if !proxied.Load() {
		t.Fatal("request did not use the proxy")
	}
	if direct.Load() {
		t.Fatal("request bypassed the proxy")
	}
}

func proxyChildRequest() error {
	client := defaultClient()
	req, err := http.NewRequest(http.MethodGet, os.Getenv("GATECHECK_UPDATE_TARGET"), nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK || string(body) != "proxied" {
		return fmt.Errorf("status %s body %q", res.Status, body)
	}
	return nil
}

func proxyChildEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		switch strings.ToLower(key) {
		case "http_proxy", "https_proxy", "no_proxy", "request_method":
			continue
		default:
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

func firstRoutableIPv4(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			return ip.String()
		}
	}
	t.Skip("no non-loopback ipv4")
	return ""
}

type cliIO struct {
	in  bytes.Buffer
	out bytes.Buffer
	err bytes.Buffer
}

func (b *cliIO) options(base, current, exe, goos, goarch string) Options {
	return Options{
		CurrentVersion: current,
		APIBase:        base,
		GOOS:           goos,
		GOARCH:         goarch,
		Executable:     exe,
		Stdin:          &b.in,
		Stdout:         &b.out,
		Stderr:         &b.err,
		AssumeYes:      true,
		IsTerminal:     func(io.Reader) bool { return false },
	}
}

func tempBinary(t *testing.T, contents string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	target := writeBinary(t, filepath.Join(dir, "real"), contents)
	link := filepath.Join(dir, "gatecheck")
	if err := os.Symlink(target, link); err != nil {
		return target, target
	}
	return link, target
}

func writeBinary(t *testing.T, pathName, contents string) string {
	t.Helper()
	if err := os.WriteFile(pathName, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}
	return pathName
}

func releaseFiles(t *testing.T, version, goos, goarch, binary, mode string) (string, map[string][]byte) {
	t.Helper()
	name, err := assetName(version, goos, goarch)
	if err != nil {
		t.Fatal(err)
	}
	archive := tarGZ(t, map[string]string{
		"README.md":      "readme",
		"LICENSE":        "license",
		"CHANGELOG.md":   "changes",
		binaryName(goos): binary,
	})
	var sumText string
	switch mode {
	case "archive":
		sumText = sha256Hex(archive) + "  " + name + "\n"
	case "binary":
		sumText = sha256Hex([]byte(binary)) + "  " + name + "\n"
	case "wrong":
		sumText = strings.Repeat("ab", 32) + "  " + name + "\n"
	case "missing":
		sumText = sha256Hex(archive) + "  other.tar.gz\n"
	case "invalid":
		sumText = "zz  " + name + "\n"
	default:
		t.Fatalf("mode %s", mode)
	}
	return name, map[string][]byte{
		name:          archive,
		checksumsName: []byte(sumText),
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func tarGZ(t *testing.T, files map[string]string) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range names {
		body := files[name]
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o755,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type releaseServer struct {
	tag    string
	assets map[string][]byte
	srv    *httptest.Server
	mu     sync.Mutex
	hits   map[string]int
}

func startGitHub(t *testing.T, tag string, assets map[string][]byte) *releaseServer {
	t.Helper()
	gh := &releaseServer{tag: tag, assets: assets, hits: map[string]int{}}
	gh.srv = httptest.NewServer(http.HandlerFunc(gh.serve))
	t.Cleanup(gh.srv.Close)
	return gh
}

func (g *releaseServer) URL() string { return g.srv.URL }

func (g *releaseServer) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("User-Agent") != epss.UserAgent() {
		http.Error(w, "bad user agent", http.StatusBadRequest)
		return
	}
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "token", http.StatusUnauthorized)
			return
		}
	}
	switch {
	case r.URL.Path == "/repos/"+repoOwner+"/"+repoName+"/releases/latest":
		if r.Header.Get("X-GitHub-Api-Version") == "" || r.Header.Get("Accept") != "application/vnd.github+json" {
			http.Error(w, "api headers", http.StatusBadRequest)
			return
		}
		g.hit("latest")
		g.writeRelease(w, "http://"+r.Host)
	case strings.HasPrefix(r.URL.Path, "/repos/"+repoOwner+"/"+repoName+"/releases/tags/"):
		if r.Header.Get("X-GitHub-Api-Version") == "" || r.Header.Get("Accept") != "application/vnd.github+json" {
			http.Error(w, "api headers", http.StatusBadRequest)
			return
		}
		g.hit("tag")
		got := strings.TrimPrefix(r.URL.Path, "/repos/"+repoOwner+"/"+repoName+"/releases/tags/")
		if unescaped, err := url.PathUnescape(got); err == nil {
			got = unescaped
		}
		if got != g.tag {
			http.NotFound(w, r)
			return
		}
		g.writeRelease(w, "http://"+r.Host)
	case strings.HasPrefix(r.URL.Path, "/download/"):
		if r.Header.Get("Accept") != "application/octet-stream" {
			http.Error(w, "accept", http.StatusBadRequest)
			return
		}
		name := path.Base(r.URL.Path)
		g.hit("download:" + name)
		body, ok := g.assets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	default:
		http.NotFound(w, r)
	}
}

func (g *releaseServer) writeRelease(w http.ResponseWriter, base string) {
	names := make([]string, 0, len(g.assets))
	for name := range g.assets {
		names = append(names, name)
	}
	sort.Strings(names)
	payload := ghRelease{TagName: g.tag}
	for _, name := range names {
		payload.Assets = append(payload.Assets, ghAsset{
			Name:               name,
			BrowserDownloadURL: base + "/download/" + url.PathEscape(name),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (g *releaseServer) hit(name string) {
	g.mu.Lock()
	g.hits[name]++
	g.mu.Unlock()
}

func (g *releaseServer) count(name string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hits[name]
}

func (g *releaseServer) downloads() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for key, count := range g.hits {
		if strings.HasPrefix(key, "download:") {
			n += count
		}
	}
	return n
}

func (g *releaseServer) snapshot() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.hits))
	for key, count := range g.hits {
		out[key] = count
	}
	return out
}

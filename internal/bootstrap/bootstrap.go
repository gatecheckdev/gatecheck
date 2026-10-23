package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gatecheckdev/gatecheck/internal/fetch"
)

// Skip means a tool was not installed and bootstrap should continue.
type Skip struct {
	Msg string
}

func (s *Skip) Error() string { return s.Msg }

// Options configures bootstrap.
type Options struct {
	Home       string
	ToolsCSV   string
	Force      bool
	List       bool
	Client     *http.Client
	GitHubBase string
	PyPIBase   string
	UserAgent  string
	Stdout     io.Writer
	Stderr     io.Writer
	Platform   Platform
}

// Bootstrap installs pinned scanners, or lists them when Options.List is set.
func Bootstrap(ctx context.Context, opts Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, err := ResolveHome(opts.Home)
	if err != nil {
		return err
	}
	opts.Home = home
	tools, err := canonicalTools(opts.ToolsCSV)
	if err != nil {
		return err
	}
	if opts.List {
		return writeList(opts.stdout(), home, tools)
	}

	var errs []error
	for _, tool := range tools {
		err := installTool(ctx, opts, tool)
		if err == nil {
			continue
		}
		var skip *Skip
		if errors.As(err, &skip) {
			fmt.Fprintln(opts.stderr(), skip.Error())
			continue
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (o Options) stdout() io.Writer {
	if o.Stdout != nil {
		return o.Stdout
	}
	return os.Stdout
}

func (o Options) stderr() io.Writer {
	if o.Stderr != nil {
		return o.Stderr
	}
	return os.Stderr
}

func (o Options) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return defaultClient()
}

func defaultClient() *http.Client {
	return &http.Client{Timeout: 0}
}

func (o Options) platform() Platform {
	if o.Platform.GOOS == "" {
		return currentPlatform()
	}
	return o.Platform
}

func (o Options) githubBase() string {
	if strings.TrimSpace(o.GitHubBase) != "" {
		return strings.TrimRight(o.GitHubBase, "/")
	}
	return "https://github.com"
}

func (o Options) pypiBase() string {
	if strings.TrimSpace(o.PyPIBase) != "" {
		return strings.TrimRight(o.PyPIBase, "/")
	}
	return "https://pypi.org"
}

func (o Options) userAgent() string {
	if strings.TrimSpace(o.UserAgent) != "" {
		return strings.TrimSpace(o.UserAgent)
	}
	return "gatecheck (+https://github.com/gatecheckdev/gatecheck)"
}

func canonicalTools(csv string) ([]string, error) {
	if strings.TrimSpace(csv) == "" {
		return []string{"grype", "syft", "gitleaks", "semgrep"}, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(csv, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		if name == "osemgrep" {
			name = "semgrep"
		}
		switch name {
		case "grype", "syft", "gitleaks", "semgrep":
		default:
			return nil, fmt.Errorf("unknown tool %q (supported: grype, syft, gitleaks, semgrep)", name)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, errors.New("no tools selected")
	}
	return out, nil
}

func installTool(ctx context.Context, opts Options, tool string) error {
	switch tool {
	case "grype":
		asset, err := grypeAsset(GrypeVersion, opts.platform())
		if err != nil {
			return err
		}
		return installGitHub(ctx, opts, "grype", "anchore/grype", GrypeVersion, asset)
	case "syft":
		asset, err := syftAsset(SyftVersion, opts.platform())
		if err != nil {
			return err
		}
		return installGitHub(ctx, opts, "syft", "anchore/syft", SyftVersion, asset)
	case "gitleaks":
		asset, err := gitleaksAsset(GitleaksVersion, opts.platform())
		if err != nil {
			return err
		}
		return installGitHub(ctx, opts, "gitleaks", "gitleaks/gitleaks", GitleaksVersion, asset)
	case "semgrep":
		return installSemgrep(ctx, opts)
	default:
		return fmt.Errorf("unknown tool %q", tool)
	}
}

func installGitHub(ctx context.Context, opts Options, tool, repo, version string, asset githubAsset) error {
	binDir := BinDir(opts.Home)
	dest := filepath.Join(binDir, asset.DestName)
	if !opts.Force && alreadyInstalled(binDir, tool, version, dest) {
		fmt.Fprintf(opts.stdout(), "%s %s already installed\n", tool, version)
		return nil
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}

	checksumURL := githubDownloadURL(opts.githubBase(), repo, version, asset.Checksum)
	assetURL := githubDownloadURL(opts.githubBase(), repo, version, asset.Asset)
	slog.Debug("download checksums", "tool", tool, "url", checksumURL)

	body, err := fetch.Get(ctx, opts.client(), checksumURL, opts.userAgent(), 8<<20)
	if err != nil {
		return fmt.Errorf("%s: %w", tool, err)
	}
	sums, err := fetch.ParseChecksums(body)
	if err != nil {
		return fmt.Errorf("%s: %w", tool, err)
	}
	want, ok := fetch.LookupChecksum(sums, asset.Asset)
	if !ok {
		return fmt.Errorf("%s: checksum file has no entry for %s", tool, asset.Asset)
	}

	archivePath := filepath.Join(binDir, ".download-"+asset.Asset)
	defer func() { _ = os.Remove(archivePath) }()
	slog.Debug("download release", "tool", tool, "url", assetURL)
	got, err := fetch.DownloadToFile(ctx, opts.client(), assetURL, archivePath, opts.userAgent())
	if err != nil {
		return fmt.Errorf("%s: %w", tool, err)
	}
	if err := fetch.CheckSHA256(got, want); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("%s: %w", tool, err)
	}

	staged := dest + ".new"
	defer func() { _ = os.Remove(staged) }()
	if err := extractBinary(archivePath, asset.Binary, staged); err != nil {
		return fmt.Errorf("%s: %w", tool, err)
	}
	if err := fetch.Replace(staged, dest); err != nil {
		return fmt.Errorf("%s: %w", tool, err)
	}
	if err := writeVersion(binDir, tool, version); err != nil {
		return fmt.Errorf("%s: %w", tool, err)
	}
	fmt.Fprintf(opts.stdout(), "installed %s %s %s\n", tool, version, dest)
	return nil
}

func githubDownloadURL(base, repo, version, asset string) string {
	return strings.TrimRight(base, "/") + "/" + repo + "/releases/download/v" + version + "/" + asset
}

func installSemgrep(ctx context.Context, opts Options) error {
	p := opts.platform()
	binDir := BinDir(opts.Home)
	dest := osemgrepPath(binDir, p)
	if !opts.Force && alreadyInstalled(binDir, "osemgrep", SemgrepVersion, dest) {
		fmt.Fprintf(opts.stdout(), "semgrep %s already installed\n", SemgrepVersion)
		return nil
	}
	if wheelMatch(p) == nil {
		return &Skip{Msg: wheelSkipMessage(p)}
	}

	indexURL := strings.TrimRight(opts.pypiBase(), "/") + "/pypi/semgrep/" + SemgrepVersion + "/json"
	slog.Debug("download semgrep index", "url", indexURL)
	body, err := fetch.Get(ctx, opts.client(), indexURL, opts.userAgent(), 8<<20)
	if err != nil {
		return fmt.Errorf("semgrep: %w", err)
	}
	wheels, err := decodeWheels(body)
	if err != nil {
		return fmt.Errorf("semgrep: %w", err)
	}
	wheel, err := SelectWheel(wheels, p)
	if errors.Is(err, errNoWheel) {
		return &Skip{Msg: wheelSkipMessage(p)}
	}
	if err != nil {
		return fmt.Errorf("semgrep: %w", err)
	}
	if strings.TrimSpace(wheel.SHA256) == "" || strings.TrimSpace(wheel.URL) == "" {
		return errors.New("semgrep: wheel is missing a url or sha256 digest")
	}

	if err := os.MkdirAll(opts.Home, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(opts.Home, ".semgrep-staging-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()

	wheelPath := filepath.Join(stage, "semgrep.whl")
	slog.Debug("download semgrep wheel", "file", wheel.Filename, "url", wheel.URL)
	got, err := fetch.DownloadToFile(ctx, opts.client(), wheel.URL, wheelPath, opts.userAgent())
	if err != nil {
		return fmt.Errorf("semgrep: %w", err)
	}
	if err := fetch.CheckSHA256(got, wheel.SHA256); err != nil {
		return fmt.Errorf("semgrep: %w", err)
	}

	payload := filepath.Join(stage, "payload")
	if err := extractOsemgrep(wheelPath, payload, p.GOOS == "windows"); err != nil {
		if errors.Is(err, errNoSemgrepCore) {
			return &Skip{Msg: fmt.Sprintf("semgrep: wheel %s does not contain semgrep-core; skipped", wheel.Filename)}
		}
		return fmt.Errorf("semgrep: %w", err)
	}
	if err := publishOsemgrep(payload, binDir, p.GOOS == "windows"); err != nil {
		return fmt.Errorf("semgrep: %w", err)
	}
	if err := writeVersion(binDir, "osemgrep", SemgrepVersion); err != nil {
		return fmt.Errorf("semgrep: %w", err)
	}
	fmt.Fprintf(opts.stdout(), "installed semgrep %s %s\n", SemgrepVersion, dest)
	return nil
}

func publishOsemgrep(stage, binDir string, windows bool) error {
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	if err := publishLibs(stage, binDir); err != nil {
		return err
	}
	if windows {
		return fetch.Replace(filepath.Join(stage, "osemgrep.exe"), filepath.Join(binDir, "osemgrep.exe"))
	}
	if err := fetch.Replace(filepath.Join(stage, "semgrep-core"), filepath.Join(binDir, "semgrep-core")); err != nil {
		return err
	}
	link := filepath.Join(binDir, "osemgrep")
	if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Symlink("semgrep-core", link)
}

func publishLibs(stage, binDir string) error {
	src := filepath.Join(stage, "libs")
	dest := filepath.Join(binDir, "libs")
	if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
		if rmErr := os.RemoveAll(dest); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return rmErr
		}
		return nil
	} else if err != nil {
		return err
	}
	return replaceDir(dest, src)
}

func replaceDir(dest, src string) error {
	backup := dest + ".bak"
	_ = os.RemoveAll(backup)
	if _, err := os.Lstat(dest); err == nil {
		if err := os.Rename(dest, backup); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(src, dest); err != nil {
		_ = os.Rename(backup, dest)
		return err
	}
	_ = os.RemoveAll(backup)
	return nil
}

func alreadyInstalled(binDir, stamp, version, dest string) bool {
	got, ok := readVersion(binDir, stamp)
	if !ok || got != version {
		return false
	}
	info, err := os.Stat(dest)
	return err == nil && !info.IsDir()
}

func readVersion(binDir, name string) (string, bool) {
	body, err := os.ReadFile(filepath.Join(binDir, name+".version"))
	if err != nil {
		return "", false
	}
	version := strings.TrimSpace(string(body))
	if version == "" {
		return "", false
	}
	return version, true
}

func writeVersion(binDir, name, version string) error {
	return fetch.AtomicWrite(filepath.Join(binDir, name+".version"), strings.NewReader(version+"\n"), 0o644)
}

func osemgrepPath(binDir string, p Platform) string {
	if p.GOOS == "windows" {
		return filepath.Join(binDir, "osemgrep.exe")
	}
	return filepath.Join(binDir, "osemgrep")
}

func writeList(w io.Writer, home string, tools []string) error {
	binDir := BinDir(home)
	fmt.Fprintf(w, "%-10s %-10s %-10s %s\n", "TOOL", "PINNED", "INSTALLED", "PATH")
	for _, tool := range tools {
		pinned := pinnedVersion(tool)
		installed, path := installedStatus(binDir, tool)
		fmt.Fprintf(w, "%-10s %-10s %-10s %s\n", tool, pinned, installed, path)
	}
	return nil
}

func pinnedVersion(tool string) string {
	switch tool {
	case "grype":
		return GrypeVersion
	case "syft":
		return SyftVersion
	case "gitleaks":
		return GitleaksVersion
	case "semgrep":
		return SemgrepVersion
	default:
		return "-"
	}
}

func installedStatus(binDir, tool string) (string, string) {
	stamp := tool
	name := tool
	if tool == "semgrep" {
		stamp = "osemgrep"
		name = "osemgrep"
	}
	path := filepath.Join(binDir, exeName(name, runtime.GOOS))
	info, err := os.Stat(path)
	exists := err == nil && !info.IsDir()
	version, stamped := readVersion(binDir, stamp)
	switch {
	case exists && stamped:
		return version, path
	case exists:
		return "unknown", path
	default:
		return "-", "-"
	}
}

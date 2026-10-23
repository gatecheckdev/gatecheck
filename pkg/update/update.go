// Package update replaces the running gatecheck binary with a GitHub release.
package update

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
)

// Options controls one update.
type Options struct {
	// CurrentVersion is the running build. Goreleaser sets it with ldflags on main.cliVersion.
	CurrentVersion string
	// TargetVersion installs that release. Empty uses the latest release.
	TargetVersion string
	// CheckOnly prints the versions and does not download.
	CheckOnly bool
	// AssumeYes skips the confirmation prompt.
	AssumeYes bool
	// Stdin is the confirmation input. Nil uses os.Stdin.
	Stdin io.Reader
	// Stdout receives the result. Nil uses os.Stdout.
	Stdout io.Writer
	// Stderr receives prompts and progress. Nil uses os.Stderr.
	Stderr io.Writer
	// GOOS selects the release asset. Empty uses the current process.
	GOOS string
	// GOARCH selects the release asset. Empty uses the current process.
	GOARCH string
	// Executable is the binary to replace. Empty uses os.Executable and resolves symlinks.
	Executable string
	// APIBase is the GitHub API root. Empty uses https://api.github.com.
	APIBase string
	// Client is the HTTP client. Nil uses a client with the default transport.
	Client *http.Client
	// IsTerminal reports whether to prompt. Nil checks whether stdin is a terminal.
	IsTerminal func(io.Reader) bool
}

// Run checks GitHub for a gatecheck release and, unless CheckOnly is set, replaces the running binary.
func Run(ctx context.Context, opt Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	opt = opt.withDefaults()
	if err := validateTarget(opt.TargetVersion); err != nil {
		return err
	}
	_, currentErr := parseSemver(opt.CurrentVersion)
	currentOK := currentErr == nil
	if !currentOK && opt.TargetVersion == "" {
		return devVersionError(opt.CurrentVersion)
	}

	rel, err := newClient(opt).fetchRelease(ctx, opt.TargetVersion)
	if err != nil {
		return err
	}
	if opt.CheckOnly {
		return reportCheck(opt, rel)
	}
	if opt.TargetVersion == "" && currentOK {
		cmp, err := compareVersions(opt.CurrentVersion, rel.Tag)
		if err != nil {
			return err
		}
		if cmp >= 0 {
			return reportNoInstall(opt, cmp, rel)
		}
	}
	return install(ctx, opt, rel, currentOK)
}

func (o Options) withDefaults() Options {
	o.CurrentVersion = strings.TrimSpace(o.CurrentVersion)
	o.TargetVersion = strings.TrimSpace(o.TargetVersion)
	o.APIBase = strings.TrimRight(strings.TrimSpace(o.APIBase), "/")
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.GOARCH == "" {
		o.GOARCH = runtime.GOARCH
	}
	o.GOOS = strings.ToLower(o.GOOS)
	o.GOARCH = strings.ToLower(o.GOARCH)
	if o.APIBase == "" {
		o.APIBase = defaultAPIBase
	}
	if o.IsTerminal == nil {
		o.IsTerminal = stdinIsTerminal
	}
	return o
}

func validateTarget(target string) error {
	if target == "" {
		return nil
	}
	if _, err := parseSemver(target); err != nil {
		return fmt.Errorf("invalid release version %q. Use vX.Y.Z", target)
	}
	return nil
}

func devVersionError(current string) error {
	shown := strings.TrimSpace(current)
	if shown == "" {
		shown = "dev"
	}
	return fmt.Errorf("this gatecheck build has no release version (%s). Pass --version vX.Y.Z to install a release", shown)
}

func reportCheck(opt Options, rel release) error {
	label := "latest"
	if opt.TargetVersion != "" {
		label = "target"
	}
	_, err := fmt.Fprintf(opt.Stdout, "current %s\n%s %s\n", displayVersion(opt.CurrentVersion), label, displayVersion(rel.Tag))
	return err
}

func reportNoInstall(opt Options, cmp int, rel release) error {
	var text string
	if cmp > 0 {
		text = fmt.Sprintf("gatecheck %s is newer than the latest release %s\n", displayVersion(opt.CurrentVersion), displayVersion(rel.Tag))
	} else {
		text = fmt.Sprintf("gatecheck %s is up to date\n", displayVersion(rel.Tag))
	}
	_, err := io.WriteString(opt.Stdout, text)
	return err
}

func install(ctx context.Context, opt Options, rel release, currentOK bool) error {
	name, err := assetName(rel.Tag, opt.GOOS, opt.GOARCH)
	if err != nil {
		return err
	}
	if _, err := rel.assetURL(name); err != nil {
		return err
	}
	if _, err := rel.assetURL(checksumsName); err != nil {
		return err
	}
	dest, err := resolveExecutable(opt.Executable)
	if err != nil {
		return err
	}
	if err := ensureWritable(dirOf(dest)); err != nil {
		return err
	}
	proceed, err := confirmInstall(opt, currentOK, rel)
	if err != nil || !proceed {
		return err
	}
	if _, err := fmt.Fprintf(opt.Stderr, "Downloading gatecheck %s for %s/%s\n", displayVersion(rel.Tag), opt.GOOS, opt.GOARCH); err != nil {
		return err
	}
	archive, err := downloadVerified(ctx, opt, rel, name)
	if err != nil {
		return err
	}
	binary, err := extractBinary(archive, opt.GOOS)
	if err != nil {
		return err
	}
	leftover, err := installBinary(dest, binary, opt.GOOS)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(opt.Stdout, "Updated %s to %s\n", dest, displayVersion(rel.Tag)); err != nil {
		return err
	}
	if leftover != "" {
		_, err = fmt.Fprintf(opt.Stderr, "Left the previous binary at %s. Remove it after this process exits.\n", leftover)
	}
	return err
}

func confirmInstall(opt Options, currentOK bool, rel release) (bool, error) {
	if opt.AssumeYes {
		return true, nil
	}
	target := displayVersion(rel.Tag)
	prompt := fmt.Sprintf("Install gatecheck %s? [y/N] ", target)
	if currentOK {
		cmp, err := compareVersions(opt.CurrentVersion, rel.Tag)
		if err != nil {
			return false, err
		}
		switch {
		case cmp < 0:
			prompt = fmt.Sprintf("Update gatecheck from %s to %s? [y/N] ", displayVersion(opt.CurrentVersion), target)
		case cmp == 0:
			prompt = fmt.Sprintf("Reinstall gatecheck %s? [y/N] ", target)
		default:
			prompt = fmt.Sprintf("Replace gatecheck %s with %s? [y/N] ", displayVersion(opt.CurrentVersion), target)
		}
	}
	if !opt.IsTerminal(opt.Stdin) {
		return false, fmt.Errorf("confirmation required to update gatecheck to %s. Re-run with --yes", target)
	}
	ok, err := ask(opt.Stdin, opt.Stderr, prompt)
	if err != nil {
		return false, err
	}
	if !ok {
		_, err = fmt.Fprintln(opt.Stderr, "update cancelled")
		return false, err
	}
	return true, nil
}

func ask(in io.Reader, out io.Writer, prompt string) (bool, error) {
	if _, err := io.WriteString(out, prompt); err != nil {
		return false, err
	}
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.TrimSpace(line)
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes"), nil
}

func stdinIsTerminal(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func downloadVerified(ctx context.Context, opt Options, rel release, name string) ([]byte, error) {
	sumURL, err := rel.assetURL(checksumsName)
	if err != nil {
		return nil, err
	}
	archiveURL, err := rel.assetURL(name)
	if err != nil {
		return nil, err
	}
	sums, err := newClient(opt).get(ctx, sumURL, checksumsName, "application/octet-stream", maxChecksums, false)
	if err != nil {
		return nil, err
	}
	if _, err := checksumFor(sums, name); err != nil {
		return nil, err
	}
	archive, err := newClient(opt).get(ctx, archiveURL, name, "application/octet-stream", maxArchive, false)
	if err != nil {
		return nil, err
	}
	if err := verifySHA256(sums, name, archive); err != nil {
		return nil, err
	}
	return archive, nil
}

// assetName is the goreleaser archive for this version and platform.
// .goreleaser.yaml sets name_template to gatecheck_<version>_<os>_<arch>
// and does not set an archive format, so goreleaser v2 uses tar.gz for every
// OS, including Windows. The version is the tag without a leading v, which is
// what {{.Version}} writes into the filename. darwin/386 is not published.
// linux and windows also publish 386. The other architectures are amd64 and arm64.
func assetName(version, goos, goarch string) (string, error) {
	parsed, err := parseSemver(version)
	if err != nil {
		return "", fmt.Errorf("invalid release version %q", strings.TrimSpace(version))
	}
	if !supportedPlatform(goos, goarch) {
		return "", fmt.Errorf("no gatecheck release asset for %s/%s", goos, goarch)
	}
	return fmt.Sprintf("gatecheck_%s_%s_%s.tar.gz", parsed.String(), goos, goarch), nil
}

func supportedPlatform(goos, goarch string) bool {
	switch goos {
	case "darwin":
		return goarch == "amd64" || goarch == "arm64"
	case "linux", "windows":
		return goarch == "386" || goarch == "amd64" || goarch == "arm64"
	default:
		return false
	}
}

func binaryName(goos string) string {
	if goos == "windows" {
		return "gatecheck.exe"
	}
	return "gatecheck"
}

func extractBinary(archive []byte, goos string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("read release archive: %w", err)
	}
	defer func() { _ = zr.Close() }()

	tr := tar.NewReader(zr)
	want := binaryName(goos)
	var found []byte
	for entries := 0; ; entries++ {
		if entries == maxTarEntries {
			return nil, errors.New("release archive has too many entries")
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read release archive: %w", err)
		}
		cleaned, err := safeArchiveName(hdr.Name)
		if err != nil {
			return nil, err
		}
		if hdr.Size < 0 || hdr.Size > maxBinary {
			return nil, fmt.Errorf("release archive entry %s is larger than %d bytes", hdr.Name, maxBinary)
		}
		// A zero type flag is a regular file in tar headers written before TypeReg.
		regular := hdr.Typeflag == tar.TypeReg || hdr.Typeflag == 0
		match := regular && path.Base(cleaned) == want
		if !match {
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return nil, fmt.Errorf("read release archive: %w", err)
			}
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("release archive contains more than one %s", want)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxBinary+1))
		if err != nil {
			return nil, fmt.Errorf("read release binary: %w", err)
		}
		if int64(len(data)) > maxBinary {
			return nil, fmt.Errorf("release binary is larger than %d bytes", maxBinary)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("release archive contains an empty %s", want)
		}
		found = data
	}
	if found == nil {
		return nil, fmt.Errorf("release archive does not contain %s", want)
	}
	return found, nil
}

func safeArchiveName(name string) (string, error) {
	if name == "" || strings.Contains(name, `\`) {
		return "", fmt.Errorf("release archive has an unsafe path %q", name)
	}
	if path.IsAbs(name) {
		return "", fmt.Errorf("release archive has an unsafe path %q", name)
	}
	cleaned := path.Clean(name)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("release archive has an unsafe path %q", name)
	}
	return cleaned, nil
}

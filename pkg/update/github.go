package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gatecheckdev/gatecheck/pkg/epss"
)

const (
	defaultAPIBase = "https://api.github.com"
	repoOwner      = "gatecheckdev"
	repoName       = "gatecheck"
	checksumsName  = "checksums.txt"

	requestTimeout = 5 * time.Minute
	maxRedirects   = 10
	maxArchive     = 64 << 20
	maxBinary      = 128 << 20
	maxChecksums   = 1 << 20
	maxReleaseJSON = 4 << 20
	maxTarEntries  = 64
)

// defaultClient uses the process proxy settings. Cloning the default transport
// keeps ProxyFromEnvironment, so HTTP_PROXY, HTTPS_PROXY, and NO_PROXY apply.
func defaultClient() *http.Client {
	transport := http.DefaultTransport
	if base, ok := transport.(*http.Transport); ok {
		transport = base.Clone()
	}
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: transport,
	}
}

type client struct {
	apiBase string
	http    *http.Client
}

func newClient(opt Options) *client {
	httpClient := opt.Client
	if httpClient == nil {
		httpClient = defaultClient()
	}
	return &client{
		apiBase: strings.TrimRight(opt.APIBase, "/"),
		http:    httpClient,
	}
}

type release struct {
	Tag    string
	Assets map[string]string
}

func (r release) assetURL(name string) (string, error) {
	u, ok := r.Assets[name]
	if !ok || strings.TrimSpace(u) == "" {
		return "", fmt.Errorf("release %s has no asset %s", displayVersion(r.Tag), name)
	}
	return u, nil
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func (c *client) fetchRelease(ctx context.Context, target string) (release, error) {
	var (
		relURL string
		what   string
		want   string
	)
	if strings.TrimSpace(target) == "" {
		relURL = c.apiBase + "/repos/" + repoOwner + "/" + repoName + "/releases/latest"
		what = "the latest gatecheck release"
	} else {
		tag, err := releaseTag(target)
		if err != nil {
			return release{}, err
		}
		want = tag
		relURL = c.apiBase + "/repos/" + repoOwner + "/" + repoName + "/releases/tags/" + url.PathEscape(tag)
		what = "gatecheck release " + tag
	}

	body, err := c.get(ctx, relURL, what, "application/vnd.github+json", maxReleaseJSON, true)
	if err != nil {
		return release{}, err
	}
	var payload ghRelease
	if err := json.Unmarshal(body, &payload); err != nil {
		return release{}, fmt.Errorf("decode %s: %w", what, err)
	}
	tag := strings.TrimSpace(payload.TagName)
	if _, err := parseSemver(tag); err != nil {
		return release{}, fmt.Errorf("gatecheck release tag %q is not a version", payload.TagName)
	}
	if want != "" {
		got, err := releaseTag(tag)
		if err != nil || got != want {
			return release{}, fmt.Errorf("gatecheck release %s returned tag %s", want, payload.TagName)
		}
	}
	assets := make(map[string]string, len(payload.Assets))
	for _, asset := range payload.Assets {
		name := strings.TrimSpace(asset.Name)
		if name == "" {
			continue
		}
		if _, exists := assets[name]; exists {
			return release{}, fmt.Errorf("release %s lists %s more than once", displayVersion(tag), name)
		}
		assets[name] = strings.TrimSpace(asset.BrowserDownloadURL)
	}
	return release{Tag: tag, Assets: assets}, nil
}

func (c *client) get(ctx context.Context, rawURL, what, accept string, limit int64, api bool) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse %s url: %w", what, err)
	}
	if err := allowedDownloadURL(parsed, c.apiBase); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", what, err)
	}
	req.Header.Set("User-Agent", epss.UserAgent())
	req.Header.Set("Accept", accept)
	if api {
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	slog.Debug("gatecheck update request", "url", rawURL)

	res, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", what, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, statusErr(res, what)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", what, limit)
	}
	return body, nil
}

func (c *client) httpClient() *http.Client {
	wrapped := *c.http
	previous := c.http.CheckRedirect
	wrapped.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("stopped after 10 redirects")
		}
		if err := allowedDownloadURL(req.URL, c.apiBase); err != nil {
			return err
		}
		if previous != nil {
			return previous(req, via)
		}
		return nil
	}
	return &wrapped
}

func allowedDownloadURL(u *url.URL, apiBase string) error {
	if u == nil {
		return errors.New("missing download url")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return errors.New("download url is missing a host")
	}
	apiURL, err := url.Parse(apiBase)
	if err != nil {
		return fmt.Errorf("parse api base: %w", err)
	}
	apiHost := strings.ToLower(apiURL.Hostname())
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if host != apiHost {
			return fmt.Errorf("refusing non-https download host %s", host)
		}
	default:
		return fmt.Errorf("refusing download url scheme %s", u.Scheme)
	}
	if host == apiHost || knownGitHubHost(host) {
		return nil
	}
	return fmt.Errorf("refusing download host %s", host)
}

func knownGitHubHost(host string) bool {
	switch host {
	case "github.com", "api.github.com", "objects.githubusercontent.com",
		"release-assets.githubusercontent.com", "github-releases.githubusercontent.com":
		return true
	default:
		return false
	}
}

func statusErr(res *http.Response, what string) error {
	snippet, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
	slog.Debug("github request failed", "what", what, "status", res.Status, "body", strings.TrimSpace(string(snippet)))
	switch res.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("%s was not found", what)
	case http.StatusForbidden, http.StatusTooManyRequests:
		return fmt.Errorf("GitHub API rate limit reached while checking for gatecheck updates (%s). Set GITHUB_TOKEN and try again", what)
	case http.StatusUnauthorized:
		return fmt.Errorf("GitHub rejected the request for %s. Check GITHUB_TOKEN", what)
	default:
		return fmt.Errorf("%s returned %s", what, res.Status)
	}
}

func verifySHA256(checksums []byte, filename string, content []byte) error {
	want, err := checksumFor(checksums, filename)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch for %s: got %s, checksums.txt has %s. Refusing to install", filename, got, want)
	}
	return nil
}

func checksumFor(data []byte, filename string) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	invalid := false
	for scanner.Scan() {
		hash, name, ok := parseChecksumLine(scanner.Text())
		if !ok || name != filename {
			continue
		}
		if !validSHA256(hash) {
			invalid = true
			continue
		}
		return strings.ToLower(hash), nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read checksums.txt: %w", err)
	}
	if invalid {
		return "", fmt.Errorf("checksum for %s in checksums.txt is invalid. Refusing to install", filename)
	}
	return "", fmt.Errorf("checksum for %s is missing from checksums.txt. Refusing to install", filename)
}

func parseChecksumLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return "", "", false
	}
	hash := fields[0]
	name := strings.TrimPrefix(fields[1], "*")
	if i := strings.IndexByte(hash, ':'); i >= 0 {
		if !strings.EqualFold(hash[:i], "sha256") {
			return "", "", false
		}
		hash = hash[i+1:]
	}
	return hash, name, true
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

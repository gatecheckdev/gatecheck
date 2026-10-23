package epss

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dustin/go-humanize"
)

const (
	envEPSSCache    = "GATECHECK_EPSS_CACHE"
	envEPSSCacheDir = "GATECHECK_EPSS_CACHE_DIR"
	maxEPSSRedirect = 8
)

// errNoEPSSDate means the URL did not redirect to a dated EPSS file.
// The caller downloads that URL without caching.
var errNoEPSSDate = errors.New("epss url did not redirect to a dated file")

var errEPSSGzip = errors.New("epss gzip")

var datedEPSSPattern = regexp.MustCompile(`(?:^|/)epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz$`)

type epssStatusError struct {
	status string
}

func (e *epssStatusError) Error() string {
	return e.status
}

// EPSS publishes one gzip file per day. The current URL redirects to
// epss_scores-YYYY-MM-DD.csv.gz, and that date is the cache key.
func loadEPSS(options *FetchOptions, logger *slog.Logger) ([]byte, error) {
	cacheDir, enabled := resolveCache(options)
	if enabled {
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			logger.Warn("epss cache disabled", "dir", cacheDir, "error", err)
			enabled = false
		}
	}

	if enabled {
		fileURL, name, err := resolveDatedFile(options.Client, options.URL)
		if err != nil {
			logger.Debug("epss date check failed, downloading file", "error", err)
		} else {
			path := filepath.Join(cacheDir, name)
			if plain, ok := readCached(path, logger); ok {
				logger.Debug("using cached epss data", "path", path, "decompressed_size", humanize.Bytes(uint64(len(plain))))
				return plain, nil
			}
			logger.Debug("request epss data from api", "url", fileURL)
			plain, err := downloadAndCache(options.Client, fileURL, path)
			if err == nil {
				return plain, nil
			}
			if fileURL == options.URL {
				return nil, err
			}
			logger.Debug("dated epss download failed, trying original url", "url", fileURL, "error", err)
		}
	}

	logger.Debug("request epss data from api")
	return downloadAndCache(options.Client, options.URL, "")
}

func resolveCache(o *FetchOptions) (string, bool) {
	if o.cacheSet && !o.cacheOn {
		return "", false
	}
	explicitOn := (o.cacheSet && o.cacheOn) || o.cacheDirSet
	if !explicitOn && cacheDisabledByEnv() {
		return "", false
	}
	if o.cacheDirSet {
		return o.cacheDir, true
	}
	if dir := strings.TrimSpace(os.Getenv(envEPSSCacheDir)); dir != "" {
		return dir, true
	}
	base, err := os.UserCacheDir()
	if err != nil {
		slog.Warn("epss cache unavailable", "error", err)
		return "", false
	}
	return filepath.Join(base, "gatecheck", "epss"), true
}

func cacheDisabledByEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envEPSSCache))) {
	case "0", "false", "off", "no", "disabled", "disable", "none":
		return true
	default:
		return false
	}
}

func epssDateFromURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	match := datedEPSSPattern.FindStringSubmatch(u.Path)
	if match == nil {
		return "", false
	}
	return match[1], true
}

func epssCacheFilename(date string) string {
	return "epss_scores-" + date + ".csv.gz"
}

func resolveDatedFile(client *http.Client, rawURL string) (string, string, error) {
	if date, ok := epssDateFromURL(rawURL); ok {
		return rawURL, epssCacheFilename(date), nil
	}

	probe := &http.Client{
		Transport: client.Transport,
		Jar:       client.Jar,
		Timeout:   client.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	current := rawURL
	seen := make(map[string]struct{})
	for hop := 0; hop < maxEPSSRedirect; hop++ {
		if _, ok := seen[current]; ok {
			return "", "", errors.New("epss redirect loop")
		}
		seen[current] = struct{}{}

		next, status, err := probeURL(probe, current)
		if err != nil {
			return "", "", err
		}
		if status < 300 || status >= 400 {
			return "", "", errNoEPSSDate
		}
		if next == "" {
			return "", "", errors.New("epss redirect missing location")
		}
		if date, ok := epssDateFromURL(next); ok {
			return next, epssCacheFilename(date), nil
		}
		current = next
	}
	return "", "", errors.New("too many epss redirects")
}

func probeURL(client *http.Client, rawURL string) (string, int, error) {
	req, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	setEPSSHeaders(req)

	res, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))

	if res.StatusCode < 300 || res.StatusCode >= 400 {
		return "", res.StatusCode, nil
	}
	loc := res.Header.Get("Location")
	if loc == "" {
		return "", res.StatusCode, nil
	}
	base, err := url.Parse(rawURL)
	if err != nil {
		return "", res.StatusCode, err
	}
	ref, err := base.Parse(loc)
	if err != nil {
		return "", res.StatusCode, err
	}
	return ref.String(), res.StatusCode, nil
}

func setEPSSHeaders(req *http.Request) {
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept-Encoding", "identity")
}

func readCached(path string, logger *slog.Logger) ([]byte, bool) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		logger.Debug("epss cache read failed", "path", path, "error", err)
		return nil, false
	}
	plain, err := gunzip(body)
	if err != nil || len(plain) == 0 {
		logger.Debug("epss cache file is unusable", "path", path, "error", err)
		if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			logger.Debug("remove bad epss cache", "path", path, "error", rmErr)
		}
		return nil, false
	}
	return plain, true
}

func downloadAndCache(client *http.Client, rawURL, cachePath string) ([]byte, error) {
	plain, compressed, err := fetchEPSS(client, rawURL)
	if err != nil {
		return nil, err
	}
	if cachePath != "" {
		if err := saveCache(cachePath, compressed); err != nil {
			slog.Warn("save epss cache", "path", cachePath, "error", err)
		}
	}
	size := humanize.Bytes(uint64(len(plain)))
	slog.Debug("successfully downloaded and decompressed epss data", "decompressed_size", size)
	return plain, nil
}

func fetchEPSS(client *http.Client, rawURL string) ([]byte, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	setEPSSHeaders(req)

	res, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, nil, &epssStatusError{status: res.Status}
	}

	compressed, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, nil, err
	}
	plain, err := gunzip(compressed)
	if err != nil {
		return nil, nil, err
	}
	if len(plain) == 0 {
		return nil, nil, errors.New("empty epss data")
	}
	return plain, compressed, nil
}

func gunzip(compressed []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errEPSSGzip, err)
	}
	plain, err := io.ReadAll(zr)
	closeErr := zr.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return plain, nil
}

func saveCache(path string, compressed []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".epss-*.partial")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	saved := false
	defer func() {
		if !saved {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(compressed); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(path)
		if err2 := os.Rename(tmpName, path); err2 != nil {
			return err2
		}
	}
	saved = true
	return nil
}

func writeEPSSError(logger *slog.Logger, err error) {
	var statusErr *epssStatusError
	switch {
	case errors.As(err, &statusErr):
		logger.Error("epss api bad status code", "res_status", statusErr.status)
	case errors.Is(err, errEPSSGzip):
		logger.Error("gzip reader", "error", err)
	default:
		logger.Error("epss api request failed during fetch data", "error", err)
	}
}

func publicEPSSError(err error) error {
	if errors.Is(err, errEPSSGzip) {
		return errors.New("failed to parse EPSS Scores. see log for details")
	}
	return errors.New("failed to get EPSS Scores. see log for details")
}

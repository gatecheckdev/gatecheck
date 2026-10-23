package epss

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	dataModel       = "v2025.03.14"
	modelDateLayout = "2006-01-02T15:04:05Z"
	// defaultEPSSURL redirects to the latest epss_scores-YYYY-MM-DD.csv.gz.
	defaultEPSSURL = "https://epss.cyentia.com"
)

// Data a representation of the CSV data from first API
type Data struct {
	ModelVersion string
	ScoreDate    time.Time
	CVEs         map[string]CVE
}

// CVE represents a row in the CSV data
//
// Values can be converted lazily to a float on read
type CVE struct {
	EPSS       string
	Percentile string
}

// EPSSValue lazy convert to float
func (c CVE) EPSSValue() float64 {
	value, err := strconv.ParseFloat(c.EPSS, 64)
	if err != nil {
		slog.Warn("failed to parse EPSS value to float", "string_value", c.EPSS)
	}
	return value
}

// PercentileValue lazy convert to float
func (c CVE) PercentileValue() float64 {
	value, err := strconv.ParseFloat(c.Percentile, 64)
	if err != nil {
		slog.Warn("failed to parse Percentile value to float", "string_value", c.Percentile)
	}
	return value
}

// Option configures an EPSS download.
type Option func(*FetchOptions)

func WithURL(url string) Option {
	if url == "" {
		return func(_ *FetchOptions) {}
	}
	return func(o *FetchOptions) {
		o.URL = url
	}
}

func WithClient(client *http.Client) Option {
	if client == nil {
		return func(_ *FetchOptions) {}
	}
	return func(o *FetchOptions) {
		o.Client = client
	}
}

// WithCache turns the local daily EPSS cache on or off.
// The default is on, in the user cache directory.
func WithCache(enabled bool) Option {
	return func(o *FetchOptions) {
		o.cacheSet = true
		o.cacheOn = enabled
	}
}

// WithCacheDir stores cached EPSS files in dir.
func WithCacheDir(dir string) Option {
	return func(o *FetchOptions) {
		if strings.TrimSpace(dir) == "" {
			return
		}
		o.cacheDir = dir
		o.cacheDirSet = true
	}
}

// FetchOptions optional settings for the request
type FetchOptions struct {
	Client *http.Client
	URL    string

	cacheDir    string
	cacheDirSet bool
	cacheSet    bool
	cacheOn     bool
}

// DefaultFetchOptions use the default client and url for today's scores
func DefaultFetchOptions() *FetchOptions {
	return &FetchOptions{
		Client: http.DefaultClient,
		URL:    defaultEPSSURL,
	}
}

// DownloadData fetches the gzipped EPSS CSV and writes the decompressed CSV to w.
// While the upstream dated filename is unchanged, later calls reuse a local copy.
func DownloadData(w io.Writer, optionFuncs ...Option) error {
	options := DefaultFetchOptions()
	for _, optionFunc := range optionFuncs {
		optionFunc(options)
	}
	if options.Client == nil {
		options.Client = http.DefaultClient
	}
	if options.URL == "" {
		options.URL = defaultEPSSURL
	}

	logger := slog.Default().With("method", "GET", "url", options.URL)
	defer func(started time.Time) {
		logger.Debug("epss csv fetch done", "elapsed", time.Since(started))
	}(time.Now())

	plain, err := loadEPSS(options, logger)
	if err != nil {
		writeEPSSError(logger, err)
		return publicEPSSError(err)
	}
	if _, err := w.Write(plain); err != nil {
		logger.Error("io copy to writer from gzip reader", "error", err)
		return errors.New("failed to get EPSS Scores. see log for details")
	}
	return nil
}

// FetchData do a GET request and gunzip on the CSV
func FetchData(destData *Data, optionFuncs ...Option) error {
	buf := new(bytes.Buffer)
	if err := DownloadData(buf, optionFuncs...); err != nil {
		return err
	}

	return ParseEPSSDataCSV(buf, destData)
}

// ParseEPSSDataCSV custom CSV parsing function
func ParseEPSSDataCSV(r io.Reader, data *Data) error {
	// Debug the total elapsed time
	defer func(started time.Time) {
		slog.Debug("csv parse done", "elapsed", time.Since(started))
	}(time.Now())

	scanner := bufio.NewScanner(r)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return err
	}
	data.CVEs = make(map[string]CVE)
	slog.Debug("parse csv metadata header")
	parts := strings.Split(scanner.Text(), ",")
	if len(parts) != 2 {
		return fmt.Errorf("failed to parse EPSS CSV, malformed metadata header: '%s'", scanner.Text())
	}

	data.ModelVersion = strings.ReplaceAll(parts[0], "#model_version:", "")

	if data.ModelVersion != dataModel {
		slog.Warn("data model does not match supported model", "want", dataModel, "got", data.ModelVersion)
	}

	scoreDate, err := time.Parse(modelDateLayout, strings.ReplaceAll(parts[1], "score_date:", ""))
	if err != nil {
		return fmt.Errorf("failed to parse EPSS CSV, invalid date format in metadata header '%s'", scanner.Text())
	}

	data.ScoreDate = scoreDate

	// Next Line should be header
	scanner.Scan()
	if scanner.Text() != "cve,epss,percentile" {
		return fmt.Errorf("failed to parse EPSS CSV, invalid header '%s'", scanner.Text())
	}

	slog.Debug("parse csv rows")

	for scanner.Scan() {
		line := scanner.Text()
		// Add the newline back in so it would make a full file hash
		values := strings.Split(line, ",")

		if len(values) != 3 {
			return fmt.Errorf("failed to parse EPSS CSV, unexpected number of items '%s'", line)
		}

		data.CVEs[values[0]] = CVE{EPSS: values[1], Percentile: values[2]}
	}

	return nil
}

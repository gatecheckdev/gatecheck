package epss

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"log/slog"
)

const dataModel = "v2023.03.01"
const modelDateLayout = "2006-01-02T15:04:05-0700"
const epssUrlTemplate = "https://epss.cyentia.com/epss_scores-%d-%s-%s.csv.gz"

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

// FetchOptions optional settings for the request
type FetchOptions struct {
	Client *http.Client
	URL    string
}

// DefaultFetchOptions use the default client and url for today's scores
func DefaultFetchOptions() FetchOptions {
	today := time.Now()
	year := today.Year()
	month := today.Format("01")
	day := today.Format("01")
	return FetchOptions{
		Client: http.DefaultClient,
		URL:    fmt.Sprintf(epssUrlTemplate, year, month, day),
	}
}

// FetchData do a GET request and gunzip on the CSV
func FetchData(data *Data, options FetchOptions) error {
	logger := slog.Default().With("method", "GET", "url", options.URL)
	defer func(started time.Time) {
		logger.Debug("csv fetch done", "elapsed", time.Since(started))
	}(time.Now())

	logger.Debug("request data from API")
	res, err := options.Client.Get(options.URL)
	if err != nil {
		logger.Error("epss api request failed during fetch data", "error", err)
		return errors.New("failed to get EPSS Scores. see log for details")
	}
	if res.StatusCode != http.StatusOK {
		logger.Error("epss api bad status code", "res_status", res.Status)
		return errors.New("failed to get EPSS Scores. see log for details")
	}

	gunzipReader, err := gzip.NewReader(res.Body)
	if err != nil {
		logger.Error("gzip reader", "error", err)
		return errors.New("failed to parse EPSS Scores. see log for details")
	}

	return parseCSVData(gunzipReader, data)
}

// parseCSVData custom CSV parsing function
func parseCSVData(r io.Reader, data *Data) error {
	// Debug the total elapsed time
	defer func(started time.Time) {
		slog.Debug("csv parse done", "elapsed", time.Since(started))
	}(time.Now())

	scanner := bufio.NewScanner(r)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return err
	}

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

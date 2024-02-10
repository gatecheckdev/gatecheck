// Package epss contains data models and the service for cross referencing vulnerabilities with EPSS scores.
package epss

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

// ErrAPI errors in EPSS API requests
var ErrAPI = errors.New("EPSS API error")

// DefaultBaseURL for EPSS FIRST API
const DefaultBaseURL = "https://epss.cyentia.com"

const (
	supportedModel  = "v2023.03.01"
	modelDateLayout = "2006-01-02T15:04:05-0700"
)

// CVE data model
type CVE struct {
	ID          string
	Severity    string
	Link        string
	ScoreDate   time.Time
	Probability float64
	Percentile  float64
}

// Scores data model for EPSS result
type Scores struct {
	EPSS       string
	Percentile string
}

// Service used to perform EPSS API request or decoding from a file
type Service struct {
	r            io.Reader
	dataStore    map[string]Scores
	modelVersion string
	scoreDate    time.Time
}

// NewService initializes internal structures, and lazily assigns reader.
func NewService(r io.Reader) *Service {
	return &Service{r: r, dataStore: make(map[string]Scores)}
}

// GrypeDenyRuleFunc returns the function used as a deny rule cross referenced with service data store
func (s *Service) GrypeDenyRuleFunc() func([]models.Match, grype.Config) error {
	grypeDenyRule := func(matches []models.Match, config grype.Config) error {
		return gcv.DenyFunc(matches, func(match models.Match) error {
			cve, _ := s.GetCVE(match)

			if config.EPSSDenyThreshold == 0 || cve.Probability == 0 {
				return nil
			}
			denyStr := strconv.FormatFloat(config.EPSSDenyThreshold, 'f', -1, 64)
			slog.Debug("grype epss validation", "threshold", denyStr)

			if cve.Probability < config.EPSSDenyThreshold {
				return nil
			}
			probStr := strconv.FormatFloat(cve.Probability, 'f', -1, 64)

			rule := fmt.Sprintf("EPSS Score Over Deny Threshold %s", denyStr)
			id := fmt.Sprintf("%s (%s)", cve.ID, probStr)
			return gcv.NewFailedRuleError(rule, id)
		})
	}

	return grypeDenyRule
}

// GrypeAllowRuleFunc returns the function used for allow rule cross referenced with internal service data store
func (s *Service) GrypeAllowRuleFunc() func(models.Match, grype.Config) bool {
	grypeAllowRule := func(match models.Match, config grype.Config) bool {
		cve, _ := s.GetCVE(match)

		if config.EPSSAllowThreshold == 0 || cve.Probability == 0 {
			return false
		}

		return cve.Probability < config.EPSSAllowThreshold
	}

	return grypeAllowRule
}

// GetCVEs returns scores corresponding to each match
func (s *Service) GetCVEs(matches []models.Match) ([]CVE, error) {
	cves := make([]CVE, 0, len(matches))
	var errs error
	for _, match := range matches {
		cve, err := s.GetCVE(match)
		errs = errors.Join(errs, err)
		cves = append(cves, cve)
	}
	return cves, errs
}

// GetCVE returns a score corresponding to a single match
func (s *Service) GetCVE(match models.Match) (CVE, error) {
	cve := CVE{
		ID:        match.Vulnerability.ID,
		Severity:  match.Vulnerability.Severity,
		Link:      match.Vulnerability.DataSource,
		ScoreDate: s.scoreDate,
	}
	scores, ok := s.dataStore[match.Vulnerability.ID]
	if !ok {
		if len(match.RelatedVulnerabilities) == 0 {
			slog.Warn("no score found", "cve", match.Vulnerability.ID)
			return cve, nil
		}
		if _, ok = s.dataStore[match.RelatedVulnerabilities[0].ID]; !ok {
			slog.Warn("no score found for related vulnerability", "cve", match.Vulnerability.ID,
				"related_cve", match.RelatedVulnerabilities[0].ID)

			return cve, nil
		}
		scores = s.dataStore[match.RelatedVulnerabilities[0].ID]
	}
	epssValue, err := strconv.ParseFloat(scores.EPSS, 64)
	if err != nil {
		return cve, fmt.Errorf("%w: failed to parse EPSS Score for ID: '%s': %v",
			gce.ErrEncoding, match.Vulnerability.ID, err)
	}
	cve.Probability = epssValue
	percentileValue, err := strconv.ParseFloat(scores.Percentile, 64)
	if err != nil {
		return cve, fmt.Errorf("%w: failed to parse Percentile for ID: '%s': %v",
			gce.ErrEncoding, match.Vulnerability.ID, err)
	}
	cve.Percentile = percentileValue
	return cve, nil
}

// Fetch uses the internal reader to fill the internal dataStore
func (s *Service) Fetch() error {
	defer func(started time.Time) { slog.Debug("decoding done", "elapsed", time.Since(started)) }(time.Now())
	scanner := bufio.NewScanner(s.r)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return err
	}
	parts := strings.Split(scanner.Text(), ",")
	if len(parts) != 2 {
		return fmt.Errorf("%w: CSV Reader detected malformed metadata header: '%s'", gce.ErrEncoding, scanner.Text())
	}

	s.modelVersion = strings.ReplaceAll(parts[0], "#model_version:", "")

	if s.modelVersion != supportedModel {
		return fmt.Errorf("%w: CSV Reader detected invalid model version: '%s'", gce.ErrEncoding, scanner.Text())
	}

	sDate, err := time.Parse(modelDateLayout, strings.ReplaceAll(parts[1], "score_date:", ""))
	if err != nil {
		return fmt.Errorf("%w: CSV Reader detected invalid date format in metadata: '%s'", gce.ErrEncoding, scanner.Text())
	}
	s.scoreDate = sDate

	// Next Line should be header
	scanner.Scan()

	if scanner.Text() != "cve,epss,percentile" {
		return fmt.Errorf("%w: CSV Reader detected malformed header: '%s'", gce.ErrEncoding, scanner.Text())
	}

	for scanner.Scan() {
		line := scanner.Text()
		// Add the newline back in so it would make a full file hash
		values := strings.Split(line, ",")

		if len(values) != 3 {
			return fmt.Errorf("%w: CSV Reader detected malformed data: %s", gce.ErrEncoding, values)
		}

		s.dataStore[values[0]] = Scores{EPSS: values[1], Percentile: values[2]}
	}

	return nil
}

// data source (API Agent / CSV File / ORAS / Buf) reader -> Service.ReadFrom(r)

// APIAgent performs the actual API query
type APIAgent struct {
	client       *http.Client
	url          string
	gunzipReader io.Reader
}

// NewAgent used to customize the client and API URL
func NewAgent(client *http.Client, baseURL string) *APIAgent {
	return &APIAgent{client: client, url: baseURL}
}

// Read standard io.Reader implementation wrapped in a API request and gunzip.
//
// Any errors from the request will be returned during read. This is to provide
// a common interface between API request and file based reading in the Service
func (a *APIAgent) Read(p []byte) (int, error) {
	if a.gunzipReader != nil {
		return a.gunzipReader.Read(p)
	}

	today := time.Now()
	endpoint := fmt.Sprintf("epss_scores-%d-%s-%s.csv.gz", today.Year(), today.Format("01"), today.Format("02"))
	url, _ := url.JoinPath(a.url, endpoint)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	slog.Debug("epss request", "method", http.MethodGet, "url", url)

	res, err := a.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: target url: '%s': %v", ErrAPI, url, err)
	}

	if res.StatusCode != http.StatusOK {
		slog.Error("epss request", "status", res.Status)
		return 0, fmt.Errorf("%w: EPSS GET Request failed", ErrAPI)
	}

	gunzipReader, err := gzip.NewReader(res.Body)
	if err != nil {
		return 0, fmt.Errorf("%w: gzip decompression of response body failed: %v", gce.ErrEncoding, err)
	}
	a.gunzipReader = gunzipReader
	return gunzipReader.Read(p)
}

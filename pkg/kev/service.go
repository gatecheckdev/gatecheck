// Package kev uses CISA's KEV Catalog for vulnerability analysis
//
// # Cyber Infrastructure and Security Agency (CISA) Known Exploited Vulnerabilities
//
// CISA maintains the authoritative source of vulnerabilities that have been exploited in the
// wild: the Known Exploited Vulnerability (KEV) catalog. CISA strongly recommends all organizations review and monitor
// the KEV catalog and prioritize remediation of the listed vulnerabilities to reduce the
// likelihood of compromise by known threat actors.
package kev

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

// FileTypeJSON filetype plaintext
const FileTypeJSON = "CISA KEV Catalog [JSON]"

// CVERecordURL will replace '%s' with the CVE for single record queries
const CVERecordURL = "https://www.cve.org/CVERecord?id=%s"

// DefaultBaseURL url for downloading the entire catalog in JSON format
const DefaultBaseURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// ErrAPI any errors while requesting the API
var ErrAPI = errors.New("KEV API error")

// Catalog data model for KEVs
type Catalog struct {
	Title           string          `json:"title"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    time.Time       `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability data model for a single record
type Vulnerability struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
}

// Service provides a validator with internal data for cross referencing
type Service struct {
	catalog *Catalog
	reader  io.Reader
}

// NewService ...
func NewService(r io.Reader) *Service {
	return &Service{reader: r, catalog: &Catalog{}}
}

// NewValidator ...
func (s *Service) NewValidator() gcv.Validator[models.Match, grype.Config] {
	return gcv.NewValidator[models.Match, grype.Config]().WithValidationRules(s.GrypeDenyRuleFunc())
}

// GrypeDenyRuleFunc denies any vulnerability matched to the KEV Vatalog
func (s *Service) GrypeDenyRuleFunc() func([]models.Match, grype.Config) error {
	denyRule := func(matches []models.Match, _ grype.Config) error {
		slog.Debug("grype kev catalog validation deny rule", "grype_vul_count", len(matches), "catalog_count", len(s.catalog.Vulnerabilities))
		return gcv.DenyFunc(matches, func(match models.Match) error {
			inCatalog := slices.ContainsFunc(s.catalog.Vulnerabilities, func(vul Vulnerability) bool {
				return match.Vulnerability.ID == vul.CveID
			})
			if !inCatalog {
				return nil
			}
			return gcv.NewFailedRuleError("Matched to KEV Catalog", match.Vulnerability.ID)
		})
	}
	return denyRule
}

// Fetch will query through the API agent or decode from a file
func (s *Service) Fetch() error {
	c, err := NewJSONDecoder().DecodeFrom(s.reader)
	if err != nil {
		return err
	}
	s.catalog = c.(*Catalog)
	return nil
}

// Catalog a copy of the catalog
func (s *Service) Catalog() Catalog {
	return *s.catalog
}

// MatchedVulnerabilities return a slice of vulnerabilities matched to the KEV Catalog
func (s *Service) MatchedVulnerabilities(r *grype.ScanReport) []models.Match {
	if r == nil || r.Matches == nil {
		return make([]models.Match, 0)
	}
	matchesInKEVCatalog := slices.DeleteFunc(r.Matches, func(m models.Match) bool {
		inCatalog := slices.ContainsFunc(s.catalog.Vulnerabilities, func(vul Vulnerability) bool {
			return m.Vulnerability.ID == vul.CveID
		})
		// Delete if not in catalog
		return !inCatalog
	})
	return matchesInKEVCatalog
}

// APIAgent wraps the API call in an io.Reader to serve as a common interface
type APIAgent struct {
	client *http.Client
	url    string
	reader io.Reader
}

// NewAgent customize the client or query URL, use DefaultBaseURL in most cases
func NewAgent(client *http.Client, url string) *APIAgent {
	return &APIAgent{client: client, url: url}
}

// Read wraps the API call to run at read time
func (a *APIAgent) Read(p []byte) (int, error) {
	kevAPIErr := fmt.Errorf("%w: KEV Download Agent '%s'", ErrAPI, a.url)
	if a.reader != nil {
		return a.reader.Read(p)
	}

	req, _ := http.NewRequest(http.MethodGet, a.url, nil)

	res, err := a.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", kevAPIErr, err)
	}

	slog.Debug("kev request", "method", http.MethodGet, "url", a.url, "status", res.Status)
	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%w: status: %s", kevAPIErr, res.Status)
	}

	a.reader = res.Body
	return a.reader.Read(p)
}

// NewJSONDecoder standard decoder for JSON with a check function for field validation
func NewJSONDecoder() *gce.JSONWriterDecoder[Catalog] {
	return gce.NewJSONWriterDecoder[Catalog](FileTypeJSON, check)
}

func check(catalog *Catalog) error {
	if catalog == nil {
		return gce.ErrFailedCheck
	}
	if catalog.Title == "" {
		return fmt.Errorf("%w: Missing Title", gce.ErrFailedCheck)
	}
	if catalog.CatalogVersion == "" {
		return fmt.Errorf("%w: Missing Version", gce.ErrFailedCheck)
	}
	if len(catalog.Vulnerabilities) < 1 {
		return fmt.Errorf("%w: Missing Vulnerabilities", gce.ErrFailedCheck)
	}
	return nil
}

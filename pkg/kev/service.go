package kev

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"golang.org/x/exp/slices"
)

/*
Cyber Infrastructure and Security Agency (CISA) Known Exploited Vulnerabilities

CISA maintains the authoritative source of vulnerabilities that have been exploited in the
wild: the Known Exploited Vulnerability (KEV) catalog. CISA strongly recommends all organizations review and monitor
the KEV catalog and prioritize remediation of the listed vulnerabilities to reduce the
likelihood of compromise by known threat actors.
*/

const FileTypeJSON = "CISA KEV Catalog [JSON]"
const CVERecordURL = "https://www.cve.org/CVERecord?id=%s"
const DefaultBaseURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

var ErrAPI = errors.New("KEV API error")

type Catalog struct {
	Title           string          `json:"title"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    time.Time       `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

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

type Service struct {
	catalog *Catalog
	reader  io.Reader
}

func NewService(r io.Reader) *Service {
	return &Service{reader: r, catalog: &Catalog{}}
}

func (s *Service) NewValidator() gcv.Validator[models.Match, grype.Config] {
	return gcv.NewValidator[models.Match, grype.Config]().WithValidationRules(s.GrypeDenyRuleFunc())
}

func (s *Service) GrypeDenyRuleFunc() func([]models.Match, grype.Config) error {
	denyRule := func(matches []models.Match, _ grype.Config) error {
		log.Infof("Grype KEV Catalog Validation Rule: Checking %d vulnerabilities", len(matches))
		return gcv.ValidateFunc(matches, func(match models.Match) error {
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

func (s *Service) Fetch() error {
	c, err := NewJSONDecoder().DecodeFrom(s.reader)
	if err != nil {
		return err
	}
	s.catalog = c.(*Catalog)
	return nil
}

func (s *Service) Catalog() Catalog {
	return *s.catalog
}

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

type APIAgent struct {
	client *http.Client
	url    string
	reader io.Reader
}

func NewAgent(client *http.Client, url string) *APIAgent {
	return &APIAgent{client: client, url: url}
}

func (a *APIAgent) Read(p []byte) (int, error) {
	kevAPIErr := fmt.Errorf("%w: KEV Download Agent '%s'", ErrAPI, a.url)
	if a.reader != nil {
		return a.reader.Read(p)
	}

	req, _ := http.NewRequest(http.MethodGet, a.url, nil)
	log.Infof("KEV GET Request URL: %s", a.url)

	res, err := a.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", kevAPIErr, err)
	}

	if res.StatusCode != http.StatusOK {
		log.Warnf("Request Status: %s", res.Status)
		return 0, fmt.Errorf("%w: status: %s", kevAPIErr, res.Status)
	}

	a.reader = res.Body
	return a.reader.Read(p)
}

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

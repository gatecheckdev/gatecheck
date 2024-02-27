package kev

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/sagikazarmark/slog-shim"
)

const DefaultBaseURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

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

func NewCatalog() *Catalog {
	return &Catalog{
		Vulnerabilities: make([]Vulnerability, 0),
	}
}

type FetchOptions struct {
	Client *http.Client
	URL    string
}

type fetchOptionFunc func(*FetchOptions)

func WithURL(url string) fetchOptionFunc {
	return func(o *FetchOptions) {
		o.URL = url
	}
}

func WithClient(client *http.Client) fetchOptionFunc {
	return func(o *FetchOptions) {
		o.Client = client
	}
}

func DefaultFetchOptions() *FetchOptions {
	return &FetchOptions{
		Client: http.DefaultClient,
		URL:    DefaultBaseURL,
	}
}

func DownloadData(w io.Writer, optionFuncs ...fetchOptionFunc) error {
	options := DefaultFetchOptions()
	for _, optionFunc := range optionFuncs {
		optionFunc(options)
	}
	logger := slog.Default().With("method", "GET", "url", options.URL)

	defer func(started time.Time) {
		logger.Debug("kev json fetch done", "elapsed", time.Since(started))
	}(time.Now())

	logger.Debug("request kev data from api")
	res, err := options.Client.Get(options.URL)

	switch {
	case err != nil:
		logger.Error("kev api request failed during fetch data", "error", err)
		return errors.New("failed to get KEV Catalog. see log for details")
	case res.StatusCode != http.StatusOK:
		logger.Error("kev api bad status code", "res_status", res.Status)
		return errors.New("failed to get KEV Catalog. see log for details")
	}

	n, err := io.Copy(w, res.Body)
	size := humanize.Bytes(uint64(n))
	if err != nil {
		logger.Error("io copy to writer from res body", "error", err)
		return errors.New("failed to get EPSS Scores. see log for details")
	}
	slog.Debug("successfully downloaded and decompressed epss data", "decompressed_size", size)
	return err
}

func FetchData(catalog *Catalog, optionFuncs ...fetchOptionFunc) error {
	buf := new(bytes.Buffer)
	if err := DownloadData(buf, optionFuncs...); err != nil {
		return err
	}

	if err := json.NewDecoder(buf).Decode(catalog); err != nil {
		slog.Error("kev api response decoding failure", "error", err)
		return errors.New("failed to get KEV Catalog. see log for details")

	}
	return nil
}

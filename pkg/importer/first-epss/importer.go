package firstEPSS

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

var ErrPartialQueryFail = errors.New("API Request failed for some CVEs")

type Importer interface {
	Query(CVEs []string) (error, []EPSSData)
}

type response struct {
	Status     string     `json:"status"`
	StatusCode int        `json:"status-code"`
	Version    string     `json:"version"`
	Access     string     `json:"access"`
	Total      int        `json:"total"`
	Offset     int        `json:"offset"`
	Limit      int        `json:"limit"`
	Data       []EPSSData `json:"data"`
}

type EPSSData struct {
	Cve        string `json:"cve"`
	Epss       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

type BasicImporter struct {
	client    *http.Client
	BatchSize int
	Endpoint  string
}

type formattedResponse struct {
	Data EPSSData
	Err  error
	CVEs []string
}

func NewImporter(c *http.Client) *BasicImporter {
	return &BasicImporter{client: c, BatchSize: 10, Endpoint: "https://api.first.org/data/v1/epss"}
}

func (b BasicImporter) Query(CVEs []string) ([]EPSSData, error) {
	c := make(chan formattedResponse)
	var wg sync.WaitGroup

	for _, CVEBatch := range batch(b.BatchSize, CVEs) {
		wg.Add(1)

		go func(items []string) {
			defer wg.Done()
			ReturnObject := formattedResponse{CVEs: items}

			req, _ := http.NewRequest(http.MethodGet, b.Endpoint, nil)
			q := req.URL.Query()
			q.Set("cvs", strings.Join(items, ","))
			req.URL.RawQuery = q.Encode()
			res, err := b.client.Do(req)
			if err != nil {
				ReturnObject.Err = err
				c <- ReturnObject
				return
			}
			if res.StatusCode != http.StatusOK {
				ReturnObject.Err = errors.New("invalid response code")
				c <- ReturnObject
				return
			}
			data := new(EPSSData)
			if err := json.NewDecoder(res.Body).Decode(data); err != nil {
				ReturnObject.Err = err
				c <- ReturnObject
				return
			}
			c <- ReturnObject

		}(CVEBatch)
	}

	go func() {
		wg.Wait()
		close(c)
	}()

	var data []EPSSData
	var badCVEs []string
	for d := range c {
		if d.Err != nil {
			badCVEs = append(badCVEs, d.CVEs...)
		}
		data = append(data, d.Data)
	}

	var err error = nil

	if len(badCVEs) != 0 {
		err = fmt.Errorf("%w: %s", ErrPartialQueryFail, strings.Join(badCVEs, ", "))
	}

	return data, err
}

// batch will group strings by a max of n, so []string{"a", "b", "c", "d", "e"} with n = 2 will return [[a,b][c,d][e]]
func batch(n int, s []string) [][]string {
	var batches [][]string

	for len(s) != 0 {
		l := n
		if len(s) < n {
			l = len(s)
		}

		batches = append(batches, s[:l])
		s = s[l:]
	}

	return batches
}

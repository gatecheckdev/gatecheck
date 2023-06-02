package epss

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gatecheckdev/gatecheck/internal/log"

	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
)

type response struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Version    string `json:"version"`
	Access     string `json:"access"`
	Total      int    `json:"total"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
	Data       []Data `json:"data"`
}

type result struct {
	data  Data
	Error error
}

func NewEPSSService(c *http.Client, endpoint string) *Service {
	return &Service{client: c, BatchSize: 10, Endpoint: endpoint}
}

type Service struct {
	client    *http.Client
	BatchSize int
	Endpoint  string
}

func (s Service) WriteCSV(w io.Writer, url string) (int64, error) {
	req, _ := http.NewRequest("GET", url, nil)

	res, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrAPIPartialFail, err)
	}

	if res.StatusCode != http.StatusOK {
		log.Warnf("Download CSV Status: %s", res.Status)
		return 0, fmt.Errorf("%w: %v", ErrAPIPartialFail, err)
	}

	reader, err := gzip.NewReader(res.Body)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrDecode, err)
	}

	n, err := io.Copy(w, reader)
	if err != nil {
		return n, fmt.Errorf("%w :%v", ErrEncode, err)
	}
	reader.Close()
	return n, nil
}

func (s Service) Get(CVEs []CVE) ([]Data, error) {
	dataChan := make(chan result)
	var wg sync.WaitGroup

	for i := 0; i < len(CVEs); i = i + s.BatchSize {
		l := i + s.BatchSize
		if l > len(CVEs) {
			l = len(CVEs)
		}
		group := CVEs[i:l]
		wg.Add(1)
		go func(g []CVE) {
			defer wg.Done()
			url := s.Endpoint + "?cve=" + commaSeperated(g)
			req, _ := http.NewRequest(http.MethodGet, url, nil)
			res, err := s.client.Do(req)
			if err != nil {
				dataChan <- result{Error: err}
				return
			}
			if res.StatusCode != http.StatusOK {
				log.Info(res.Status)
				dataChan <- result{Error: errors.New("received non 200 response")}
			}
			var resObj response
			err = json.NewDecoder(res.Body).Decode(&resObj)

			if err != nil {
				dataChan <- result{Error: err}
				return
			}

			inputMap := cveMap(CVEs)
			for _, returnedData := range resObj.Data {
				returnedData.URL = inputMap[returnedData.CVE].Link
				returnedData.Severity = inputMap[returnedData.CVE].Severity
				dataChan <- result{data: returnedData}
			}
		}(group)
	}

	go func() {
		wg.Wait()
		close(dataChan)
	}()

	var data []Data
	var err error

	for d := range dataChan {
		data = append(data, d.data)
		if d.Error != nil {
			err = ErrAPIPartialFail
		}
	}

	return data, err
}

func commaSeperated(CVEs []CVE) string {
	items := make([]string, len(CVEs))
	for i, v := range CVEs {
		items[i] = v.ID
	}
	return strings.Join(items, ",")
}

func cveMap(CVEs []CVE) map[string]CVE {
	out := make(map[string]CVE)

	for _, v := range CVEs {
		out[v.ID] = v
	}
	return out
}

func Sprint(data []Data) string {

	table := new(gcStrings.Table).WithHeader("CVE", "Severity", "EPSS", "Percentile", "Date", "Link")

	percentage := func(s string) string {
		f, _ := strconv.ParseFloat(s, 64)

		return fmt.Sprintf("%.2f%%", 100*f)
	}

	for _, d := range data {
		table = table.WithRow(d.CVE, d.Severity, percentage(d.EPSS), percentage(d.Percentile), d.Date, d.URL)
	}

	// Dsc because EPSS has been converted into a percentage
	table = table.SortBy([]gcStrings.SortBy{
		{Name: "EPSS", Mode: gcStrings.Dsc},
	}).Sort()

	return table.String()
}

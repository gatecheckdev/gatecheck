package epss

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gatecheckdev/gatecheck/internal/log"

	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
)

type response struct {
	Status     string         `json:"status"`
	StatusCode int            `json:"status-code"`
	Version    string         `json:"version"`
	Access     string         `json:"access"`
	Total      int            `json:"total"`
	Offset     int            `json:"offset"`
	Limit      int            `json:"limit"`
	Data       []ResponseData `json:"data"`
}

type ResponseData struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
	Severity   string `json:"severity,omitempty"`
	URL        string `json:"url,omitempty"`
}

type result struct {
	data  ResponseData
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
	defer func(started time.Time) { log.Infof("EPSS CSV writing completed in %s", time.Since(started).String()) }(time.Now())
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

// WriteEPSS will write probability and percentile scores to each element in input querying on the ID field
func (s Service) WriteEPSS(input []CVE) error {
	defer func(started time.Time) { log.Infof("WriteEPSS for %d CVEs completed in %s", len(input), time.Since(started).String()) }(time.Now())

	if len(input) == 0 || input == nil {
		return nil
	}
	index := 0
	end := s.BatchSize
	errChan := make(chan error)
	doneChan := make(chan struct{})
	min := func(a int, b int) int {
		return int(math.Min(float64(a), float64(b)))
	}
	var wg sync.WaitGroup

	for index < len(input) {
		end = min(index+s.BatchSize, len(input))
		wg.Add(1)
		go executeQuery(s, input[index:end], errChan, &wg)
		index += s.BatchSize
	}

	go func() {
		wg.Wait()
		doneChan <- struct{}{}
	}()

	select {
	case <-doneChan:
		return nil
	case err := <-errChan:
		return err
	}
}

func executeQuery(s Service, input []CVE, errChan chan error, wg *sync.WaitGroup) {
	defer wg.Done()
	ids := make([]string, len(input))
	for i := range ids {
		ids[i] = input[i].ID
	}
	url := s.Endpoint + "?cve=" + strings.Join(ids, ",")
	res, err := s.client.Get(url)
	if err != nil {
		errChan <- fmt.Errorf("%w: %s", ErrAPIPartialFail, err)
		return
	}
	if res.StatusCode != http.StatusOK {
		log.Warn(url)
		log.Warn(res.Status)
		errChan <- fmt.Errorf("%w: %s", ErrAPIPartialFail, res.Status)
		return
	}
	var resObj response
	if err := json.NewDecoder(res.Body).Decode(&resObj); err != nil {
		errChan <- fmt.Errorf("%w: %v", ErrDecode, err)
		return
	}

	inputMap := make(map[string]*CVE, len(input))
	for i := range input {
		inputMap[input[i].ID] = &input[i]
	}

	for _, data := range resObj.Data {
		inputMap[data.CVE].Link = data.URL
		prob, err := strconv.ParseFloat(data.EPSS, 64)
		if err != nil {
			errChan <- fmt.Errorf("%w: %v", ErrDecode, err)
			return
		}
		perc, err := strconv.ParseFloat(data.Percentile, 64)
		if err != nil {
			errChan <- fmt.Errorf("%w: %v", ErrDecode, err)
			return
		}
		inputMap[data.CVE].Probability = prob
		inputMap[data.CVE].Percentile = perc
	}
}

func Sprint(input []CVE) string {

	table := new(gcStrings.Table).WithHeader("CVE", "Severity", "EPSS", "Percentile", "Date", "Link")

	percentage := func(f float64) string {
		return fmt.Sprintf("%.2f%%", 100*f)
	}

	for _, cve := range input {
		table = table.WithRow(cve.ID, cve.Severity, percentage(cve.Probability), percentage(cve.Percentile), cve.ScoreDate.Format("2006-01-02"), cve.Link)
	}

	// Dsc because EPSS has been converted into a percentage
	table = table.SortBy([]gcStrings.SortBy{
		{Name: "EPSS", Mode: gcStrings.Dsc},
	}).Sort()

	return table.String()
}

package epss

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"golang.org/x/exp/rand"
)

const epssTestFilename = "../../test/epss_scores-2023-06-01.csv"

func TestAPIAgent(t *testing.T) {

	mockServer := MockEPSSServer(t)
	outputBuf := new(bytes.Buffer)
	n, err := outputBuf.ReadFrom(NewAgent(mockServer.Client(), mockServer.URL))
	if err != nil {
		t.Fatal(n, err)
	}
}

func TestService_GetCVEs(t *testing.T) {
	service := &Service{
		dataStore: map[string]Scores{
			"cve-1": {EPSS: fmt.Sprintf("%.5f", rand.Float64()), Percentile: fmt.Sprintf("%.5f", rand.Float64())},
			"cve-2": {EPSS: fmt.Sprintf("%.5f", rand.Float64()), Percentile: fmt.Sprintf("%.5f", rand.Float64())},
			"cve-3": {EPSS: "not a real number", Percentile: fmt.Sprintf("%.5f", rand.Float64())},
			"cve-4": {EPSS: fmt.Sprintf("%.5f", rand.Float64()), Percentile: "not a real number"},
		},
	}

	matches := []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-2"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "ghsa-1"}},
			RelatedVulnerabilities: []models.VulnerabilityMetadata{{ID: "cve-1"}}},
	}
	t.Run("found", func(t *testing.T) {
		cves, err := service.GetCVEs(matches)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(cves)
		if cves[0].Probability == 0 || cves[0].Percentile == 0 {
			t.FailNow()
		}
		if cves[1].Probability == 0 || cves[1].Percentile == 0 {
			t.FailNow()
		}
	})

	t.Run("not-found", func(t *testing.T) {
		matches := append(matches, models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-5"}}})
		cves, err := service.GetCVEs(matches)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(cves)
		if cves[3].Probability != 0 || cves[3].Percentile != 0 {
			t.Fatal("Prob and Percentile should be 0:", cves[3])
		}
	})

	t.Run("not-found-or-related-not-found", func(t *testing.T) {
		matches := append(matches, models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "ghsa-5"}},
			RelatedVulnerabilities: []models.VulnerabilityMetadata{{ID: "cve-5"}}})
		cves, err := service.GetCVEs(matches)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(cves)
		if cves[3].Probability != 0 || cves[3].Percentile != 0 {
			t.Fatal("Prob and Percentile should be 0:", cves[3])
		}
	})

	t.Run("bad-parse", func(t *testing.T) {
		matches := append(matches, models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-3"}}})
		matches = append(matches, models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-4"}}})
		_, err := service.GetCVEs(matches)
		t.Log(err)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatal(err)
		}

	})
}

func TestService(t *testing.T) {
	badMeatadata := "#model_version:v2099.03.01,score_date:2023-07-14T00:00:00+0000"
	badMetadataDate := "#model_version:v2023.03.01,score_date:2023abdef00+0000"
	goodVersion := "#model_version:v2023.03.01,score_date:2023-07-14T00:00:00+0000"
	badHeader := "\nfooo,epss,percentile"
	goodHeader := "\ncve,epss,percentile"
	badBody := "\nCVE-1999-0001,0.01167,0.83060,foo,bar"

	mockServer := MockEPSSServer(t)
	mockServer2 := MockBadStatusServer(t)
	mockServer3 := mockBadContentService(t)
	testTable := []struct {
		label   string
		reader  io.Reader
		wantErr error
	}{
		{label: "success-agent", reader: NewAgent(mockServer.Client(), mockServer.URL), wantErr: nil},
		{label: "success-file", reader: MustOpen(epssTestFilename, t), wantErr: nil},
		{label: "fail-agent-url", reader: NewAgent(mockServer.Client(), ""), wantErr: ErrAPI},
		{label: "fail-agent-status", reader: NewAgent(mockServer2.Client(), mockServer2.URL), wantErr: ErrAPI},
		{label: "fail-agent-content", reader: NewAgent(mockServer3.Client(), mockServer3.URL), wantErr: gce.ErrEncoding},
		{label: "malform-header", reader: strings.NewReader("1,2,3,4,5,6"), wantErr: gce.ErrEncoding},
		{label: "bad-metadata", reader: strings.NewReader(badMeatadata), wantErr: gce.ErrEncoding},
		{label: "bad-metadata-date", reader: strings.NewReader(badMetadataDate), wantErr: gce.ErrEncoding},
		{label: "bad-date", reader: strings.NewReader(goodVersion + badHeader), wantErr: gce.ErrEncoding},
		{label: "bad-version", reader: strings.NewReader(goodVersion + goodHeader + badBody), wantErr: gce.ErrEncoding},
	}

	for _, c := range testTable {
		t.Run(c.label, func(t *testing.T) {
			service := NewService(c.reader)
			err := service.Fetch()

			if !errors.Is(err, c.wantErr) {
				t.Fatalf("want: %v got: %v", c.wantErr, err)
			}
			if err != nil {
				t.Log(err)
				return
			}
			i := 0
			for key := range service.dataStore {
				i++
				if i == 10 {
					break
				}
				t.Log(service.dataStore[key])
				if len(service.dataStore[key].EPSS) != 7 || len(service.dataStore[key].Percentile) != 7 {
					t.FailNow()
				}
			}

		})
	}
}

func TestServiceFetch(t *testing.T) {
	mockServer := MockEPSSServer(t)
	service := NewService(NewAgent(mockServer.Client(), mockServer.URL))
	if err := service.Fetch(); err != nil {
		t.Fatal(err)
	}
	i := 0
	for key := range service.dataStore {
		i++
		if i == 10 {
			break
		}
		t.Log(service.dataStore[key])
	}
}

func MockEPSSServer(t *testing.T) *httptest.Server {

	inputBuf := new(bytes.Buffer)
	writer := gzip.NewWriter(inputBuf)
	_, _ = io.Copy(writer, MustOpen(epssTestFilename, t))
	writer.Close()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, inputBuf)
	}))
	return mockServer
}

func MockBadStatusServer(t *testing.T) *httptest.Server {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	return mockServer
}

func mockBadContentService(t *testing.T) *httptest.Server {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"key": "value"})
	}))
	return mockServer

}

func MustOpen(filename string, t *testing.T) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func almostEqual(a float64, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

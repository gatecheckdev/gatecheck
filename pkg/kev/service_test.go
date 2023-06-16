package kev

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
)

func TestService_MatchedVulnerabilities(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		service := &Service{catalog: &Catalog{
			Vulnerabilities: []Vulnerability{
				{CveID: "cve-1"}, {CveID: "cve-3"}, {CveID: "cve-5"}, {CveID: "cve-7"}, {CveID: "cve-9"},
			},
		}}
		report := &grype.ScanReport{Matches: make([]models.Match, 10)}
		for i := range report.Matches {
			report.Matches[i].Vulnerability.ID = fmt.Sprintf("cve-%d", i)
		}
		for _, match := range service.MatchedVulnerabilities(report) {
			t.Log(match.Vulnerability.ID)
		}
		t.Log(service.Catalog().Vulnerabilities)
	})

	t.Run("success-no-vulnerabilities", func(t *testing.T) {
		service := NewService(MustOpen("../../test/known_exploited_vulnerabilities.json", t))
		if err := service.Fetch(); err != nil {
			t.Fatal(err)
		}
		denied := service.MatchedVulnerabilities(nil)
		t.Log(denied)
		denied = service.MatchedVulnerabilities(&grype.ScanReport{Matches: make([]models.Match, 0)})
		t.Log(denied)
	})

	t.Run("decode-fail", func(t *testing.T) {
		err := NewService(strings.NewReader("{{{")).Fetch()
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatal(err)
		}
	})
}

func TestAgent_Read(t *testing.T) {
	mockSuccessServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		catalog := &Catalog{
			Title:          "some title",
			CatalogVersion: "some version",
			Vulnerabilities: []Vulnerability{
				{CveID: "cve-1"}, {CveID: "cve-3"}, {CveID: "cve-5"}, {CveID: "cve-7"}, {CveID: "cve-9"},
			},
		}
		json.NewEncoder(w).Encode(catalog)
	}))

	t.Run("success", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(NewAgent(mockSuccessServer.Client(), mockSuccessServer.URL))
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewJSONDecoder().DecodeFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if c.(*Catalog).Vulnerabilities[0].CveID != "cve-1" {
			t.FailNow()
		}
	})

	t.Run("bad-server", func(t *testing.T) {
		mockClosedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		mockClosedServer.Close()
		_, err := NewAgent(mockClosedServer.Client(), mockClosedServer.URL).Read(make([]byte, 2))
		t.Log(err)
		if !errors.Is(err, ErrAPI) {
			t.Fatalf("want: %v got: %v", ErrAPI, err)
		}
	})
	t.Run("bad-status", func(t *testing.T) {
		mockFailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		_, err := NewAgent(mockFailServer.Client(), mockFailServer.URL).Read(make([]byte, 2))
		t.Log(err)
		if !errors.Is(err, ErrAPI) {
			t.Fatalf("want: %v got: %v", ErrAPI, err)
		}
	})
}

func TestCheckFunc(t *testing.T) {
	var catalog *Catalog
	if err := check(nil); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}
	catalog = new(Catalog)
	if err := check(catalog); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}
	catalog.Title = "some title"
	if err := check(catalog); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}
	catalog.CatalogVersion = "some version"
	if err := check(catalog); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
	}
	catalog.Vulnerabilities = []Vulnerability{{CveID: "cve-1"}, {CveID: "cve-2"}}
	if err := check(catalog); err != nil {
		t.Fatal(err)
	}
}

func MustOpen(filename string, t *testing.T) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

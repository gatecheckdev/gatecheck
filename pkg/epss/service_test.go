package epss

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const FirstAPIURL = "https://api.first.org/data/v1/epss"

func TestFirstAPIService_GetAll(t *testing.T) {
	server := mockClient(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resObj := response{
			Status:     "OK",
			StatusCode: 200,
			Version:    "1.0",
			Access:     "public",
			Total:      5,
			Offset:     0,
			Limit:      100,
		}
		parts := strings.Split(r.URL.Query().Get("cve"), ",")
		for _, c := range parts {
			resObj.Data = append(resObj.Data, Data{CVE: c, EPSS: "1.1", Percentile: "2.2", Date: "2022-1-1"})
		}
		_ = json.NewEncoder(w).Encode(&resObj)
	})

	service := NewEPSSService(server.Client(), FirstAPIURL)
	service.Endpoint = server.URL
	service.BatchSize = 2

	res, err := service.Get([]CVE{
		{ID: "CVE-2022-E", Severity: "Critical", Link: "some-url.com/?data=5"},
		{ID: "CVE-2022-A", Severity: "Critical", Link: "some-url.com/?data=2"},
		{ID: "CVE-2022-D", Severity: "High", Link: "some-url.com/?data=3"},
		{ID: "CVE-2022-C", Severity: "Medium", Link: "some-url.com/?data=8"},
		{ID: "CVE-2022-B", Severity: "High", Link: "some-url.com/?data=1"},
	})

	if err != nil {
		t.Fatal(err)
	}

	t.Log("\n" + Sprint(res))

}

func TestFirstAPIService_BadServer(t *testing.T) {
	server := mockClient(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Server Error"})
	})

	service := NewEPSSService(server.Client(), FirstAPIURL)
	service.Endpoint = server.URL

	_, err := service.Get([]CVE{{ID: "a"}, {ID: "b"}})

	if errors.Is(err, ErrAPIPartialFail) != true {
		t.Fatal(err)
	}
}

func TestFirstAPIService_ClosedSever(t *testing.T) {
	server := mockClient(func(w http.ResponseWriter, r *http.Request) {})
	server.Close()

	service := NewEPSSService(server.Client(), FirstAPIURL)
	service.Endpoint = server.URL

	_, err := service.Get([]CVE{{ID: "a"}, {ID: "b"}})
	if errors.Is(err, ErrAPIPartialFail) != true {
		t.Fatal(err)
	}
}

func TestFirstAPIService_BadServerResponseJSON(t *testing.T) {
	server := mockClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{BAD JSON"))
	})

	service := NewEPSSService(server.Client(), FirstAPIURL)
	service.Endpoint = server.URL

	_, err := service.Get([]CVE{{ID: "a"}, {ID: "b"}})
	if errors.Is(err, ErrAPIPartialFail) != true {
		t.Fatal(err)
	}
}

func mockClient(handlerFunc func(http.ResponseWriter, *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handlerFunc))
}

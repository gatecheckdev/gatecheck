package firstEPSS

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBasicImporter_Query(t *testing.T) {
	server := mockClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "Application/json")
		resObj := response{
			Status:     "OK",
			StatusCode: 200,
			Version:    "1.0",
			Access:     "public",
			Total:      5,
			Offset:     0,
			Limit:      100,
		}
		for _, values := range r.URL.Query() {
			resObj.Data = append(resObj.Data, EPSSData{
				Cve:        values[0],
				Epss:       "1.1",
				Percentile: "12",
				Date:       time.Now().String(),
			})
		}
		_ = json.NewEncoder(w).Encode(&resObj)
	})

	importer := NewImporter(server.Client())
	importer.BatchSize = 2
	importer.Endpoint = server.URL

	_, err := importer.Query([]string{"a", "b", "c", "d", "e"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBasicImporter_QueryBadServer(t *testing.T) {
	server := mockClient(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		t.Log(q.Get("cvs"))
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "Application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Server Error"})
	})

	importer := NewImporter(server.Client())
	importer.BatchSize = 2
	importer.Endpoint = server.URL

	_, err := importer.Query([]string{"a", "b", "c", "d", "e"})
	if errors.Is(err, ErrPartialQueryFail) != true {
		t.Fatal(err)
	}
}

func TestBasicImporter_QueryClosedSever(t *testing.T) {
	server := mockClient(func(w http.ResponseWriter, r *http.Request) {})
	server.Close()

	importer := NewImporter(server.Client())
	importer.BatchSize = 2
	importer.Endpoint = server.URL

	_, err := importer.Query([]string{"a", "b", "c", "d", "e"})
	if errors.Is(err, ErrPartialQueryFail) != true {
		t.Fatal(err)
	}
}

func TestBasicImporter_QueryBadServerResponseJSON(t *testing.T) {
	server := mockClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{BAD JSON"))
	})

	importer := NewImporter(server.Client())
	importer.BatchSize = 2
	importer.Endpoint = server.URL

	_, err := importer.Query([]string{"a", "b", "c", "d", "e"})
	if errors.Is(err, ErrPartialQueryFail) != true {
		t.Fatal(err)
	}
}

func mockClient(handlerFunc func(http.ResponseWriter, *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handlerFunc))
}

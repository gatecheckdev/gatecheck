package epss

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestService_WriteCSV(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		server := mockServer(func(w http.ResponseWriter, r *http.Request) {
			mockCSV := "#model_version:v2023.03.01,score_date:2023-06-01T00:00:00+0000\ncve,epss,percentile\n1,2,3"

			buf := new(bytes.Buffer)
			writer := gzip.NewWriter(buf)
			_, _ = writer.Write([]byte(mockCSV))
			writer.Close()

			w.Write(buf.Bytes())
		})

		outputBuf := new(bytes.Buffer)

		service := NewEPSSService(server.Client(), server.URL)

		if _, err := service.WriteCSV(outputBuf, server.URL); err != nil {
			t.Fatal(err)
		}
		t.Log(outputBuf)

	})

	t.Run("bad-writer", func(t *testing.T) {
		server := mockServer(func(w http.ResponseWriter, r *http.Request) {
			mockCSV := "#model_version:v2023.03.01,score_date:2023-06-01T00:00:00+0000\ncve,epss,percentile\n1,2,3"

			buf := new(bytes.Buffer)
			writer := gzip.NewWriter(buf)
			_, _ = writer.Write([]byte(mockCSV))
			writer.Close()

			w.Write(buf.Bytes())
		})

		service := NewEPSSService(server.Client(), server.URL)

		if _, err := service.WriteCSV(badWriter{}, server.URL); !errors.Is(err, ErrEncode) {
			t.Fatal(err, "Expected Decode Failure")
		}
	})

	t.Run("Bad-decode", func(t *testing.T) {
		server := mockServer(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"msg": "Some JSON, not GZIP"})
			w.WriteHeader(http.StatusOK)
		})

		service := NewEPSSService(server.Client(), server.URL)
		buf := new(bytes.Buffer)

		if _, err := service.WriteCSV(buf, server.URL); !errors.Is(err, ErrDecode) {
			t.Fatal(err, "Expected Decode Failure")
		}
	})

	t.Run("client-failure", func(t *testing.T) {
		server := mockServer(func(w http.ResponseWriter, r *http.Request) {})
		server.Close()

		service := NewEPSSService(server.Client(), server.URL)
		buf := new(bytes.Buffer)

		if _, err := service.WriteCSV(buf, server.URL); !errors.Is(err, ErrAPIPartialFail) {
			t.Fatal(err, "Expected API Failure")
		}

	})

	t.Run("bad-status", func(t *testing.T) {
		server := mockServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		})

		service := NewEPSSService(server.Client(), server.URL)
		buf := new(bytes.Buffer)

		if _, err := service.WriteCSV(buf, server.URL); !errors.Is(err, ErrAPIPartialFail) {
			t.Fatal(err, "Expected API Failure")
		}

	})

}

func TestService_GetAll(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
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

	service := NewEPSSService(server.Client(), server.URL)
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

func TestService_BadServer(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Server Error"})
	})

	service := NewEPSSService(server.Client(), server.URL)
	service.Endpoint = server.URL

	_, err := service.Get([]CVE{{ID: "a"}, {ID: "b"}})

	if errors.Is(err, ErrAPIPartialFail) != true {
		t.Fatal(err)
	}
}

func TestService_ClosedSever(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {})
	server.Close()

	service := NewEPSSService(server.Client(), server.URL)
	service.Endpoint = server.URL

	_, err := service.Get([]CVE{{ID: "a"}, {ID: "b"}})
	if errors.Is(err, ErrAPIPartialFail) != true {
		t.Fatal(err)
	}
}

func TestService_BadServerResponseJSON(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{BAD JSON"))
	})

	service := NewEPSSService(server.Client(), server.URL)
	service.Endpoint = server.URL

	_, err := service.Get([]CVE{{ID: "a"}, {ID: "b"}})
	if errors.Is(err, ErrAPIPartialFail) != true {
		t.Fatal(err)
	}
}

func mockServer(h func(http.ResponseWriter, *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(h))
}

type badWriter struct{}

func (b badWriter) Write(_ []byte) (n int, err error) {
	return 0, errors.New("mock error")
}

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

func TestService_WriteEPSS(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := mockServerWithData()
		service := NewEPSSService(server.Client(), server.URL)

		cves := []CVE{{ID: "CVE-2022-A"}, {ID: "CVE-2022-B"}, {ID: "CVE-2022-C"}, {ID: "CVE-2022-D"}, {ID: "CVE-2022-E"}}

		if err := service.WriteEPSS(cves); err != nil {
			t.Fatal(err)
		}
		for _, v := range cves {
			if almostEqual(v.Probability, float64(0)) {
				t.Fatalf("%+v probability almost equal to zero", v)
			}
			if almostEqual(v.Percentile, float64(0)) {
				t.Fatalf("%+v percentile almost equal to zero", v)
			}
		}
		t.Log(Sprint(cves))
	})

	t.Run("len-zero", func(t *testing.T) {
		server := mockServerWithData()
		service := NewEPSSService(server.Client(), server.URL)
		if err := service.WriteEPSS([]CVE{}); err != nil {
			t.Fatal(err)
		}
		if err := service.WriteEPSS(nil); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("bad-request", func(t *testing.T) {
		server := mockServerWithData()
		service := NewEPSSService(server.Client(), server.URL)
		server.Close()
		if err := service.WriteEPSS([]CVE{{ID: "CVE-2022-A"}}); !errors.Is(err, ErrAPIPartialFail) {
			t.Fatal(err)
		}
	})

	t.Run("bad-request", func(t *testing.T) {
		server := mockServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		})
		service := NewEPSSService(server.Client(), server.URL)
		if err := service.WriteEPSS([]CVE{{ID: "CVE-2022-A"}}); !errors.Is(err, ErrAPIPartialFail) {
			t.Fatal(err)
		}
	})

	t.Run("decode-error", func(t *testing.T) {
		server := mockServer(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("{{{"))
		})
		service := NewEPSSService(server.Client(), server.URL)
		if err := service.WriteEPSS([]CVE{{ID: "CVE-2022-A"}}); !errors.Is(err, ErrDecode) {
			t.Fatal(err)
		}
	})

	t.Run("parsing-errors", func(t *testing.T) {
		server := mockServerWithCustomData([]ResponseData{{CVE: "CVE-2022-A", Percentile: "abc", EPSS: "0.09931"}})
		service := NewEPSSService(server.Client(), server.URL)
		if err := service.WriteEPSS([]CVE{{ID: "CVE-2022-A"}}); !errors.Is(err, ErrDecode) {
			t.Fatal(err)
		}

		server = mockServerWithCustomData([]ResponseData{{CVE: "CVE-2022-A", Percentile: "0.09319", EPSS: "abc"}})
		service = NewEPSSService(server.Client(), server.URL)
		if err := service.WriteEPSS([]CVE{{ID: "CVE-2022-A"}}); !errors.Is(err, ErrDecode) {
			t.Fatal(err)
		}

	})

}

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

func mockServer(h func(http.ResponseWriter, *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(h))
}

func mockServerWithData() *httptest.Server {
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
			resObj.Data = append(resObj.Data, ResponseData{CVE: c, EPSS: "1.1", Percentile: "2.2", Date: "2022-1-1"})
		}

		_ = json.NewEncoder(w).Encode(&resObj)
	})

	return server
}

func mockServerWithCustomData(input []ResponseData) *httptest.Server {
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

		resObj.Data = input

		_ = json.NewEncoder(w).Encode(&resObj)
	})

	return server
}

type badWriter struct{}

func (b badWriter) Write(_ []byte) (n int, err error) {
	return 0, errors.New("mock error")
}

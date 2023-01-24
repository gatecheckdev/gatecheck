package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func Test_query(t *testing.T) {
	t.Run("closed-server", func(t *testing.T) {
		server := httptest.NewServer(nopHandler())
		server.Close()
		_, err := query[struct{ A string }](server.Client(), "", server.URL, alwaysTrue[struct{ A string }])
		if err == nil {
			t.Fatal("Expected request error for closed server")
		}
	})

	t.Run("bad-response", func(t *testing.T) {
		server := httptest.NewServer(badStatusHandler())
		_, err := query[struct{ A string }](server.Client(), "", server.URL, alwaysTrue[struct{ A string }])
		if err == nil {
			t.Fatal("Expected request error for closed server")
		}
	})

	t.Run("bad-decode", func(t *testing.T) {
		server := httptest.NewServer(badDecodeHandler(http.StatusOK))
		_, err := query[struct{ A string }](server.Client(), "", server.URL, alwaysTrue[struct{ A string }])
		if err == nil {
			t.Fatal("Expected request error for closed server")
		}
	})

	t.Run("success", func(t *testing.T) {
		first := paginatedResponse[TestStruct]{
			Results: []TestStruct{{A: "non match"}, {A: "non match"}},
		}
		second := paginatedResponse[TestStruct]{
			Results: []TestStruct{{A: "non match"}, {A: "test test"}},
		}
		server := httptest.NewServer(customResponseWithNext(http.StatusOK, &first, &second))
		first.Next = server.URL + "/second"

		var matchFunc = func(v TestStruct) bool {
			return v.A == "test test"
		}

		resObj, err := query[TestStruct](server.Client(), "", server.URL, matchFunc)
		if err != nil {
			t.Fatal(err)
		}

		if resObj.A != "test test" {
			t.Fatal("Unexpected response object")
		}
	})

	t.Run("not-found", func(t *testing.T) {
		returnObj := paginatedResponse[TestStruct]{
			Results: []TestStruct{{A: "non match"}, {A: "non match"}},
		}
		server := httptest.NewServer(customResponseHandler(http.StatusOK, &returnObj))

		_, err := query[TestStruct](server.Client(), "", server.URL, alwaysFalse[TestStruct])
		if errors.Is(err, errNotFound) != true {
			t.Fatal("Expected not found error")
		}
	})
}

func TestService_postJSON(t *testing.T) {
	t.Run("closed-server", func(t *testing.T) {
		server := httptest.NewServer(nopHandler())
		server.Close()
		service := NewService(server.Client(), "", server.URL)
		b, _ := json.Marshal(TestStruct{A: "test test"})
		if _, err := service.postJSON(service.url, bytes.NewBuffer(b)); err == nil {
			t.Fatal("Expected error for closed server")
		}
	})
	t.Run("bad-status", func(t *testing.T) {
		server := httptest.NewServer(badStatusHandler())
		service := NewService(server.Client(), "", server.URL)
		b, _ := json.Marshal(TestStruct{A: "test test"})
		if _, err := service.postJSON(service.url, bytes.NewBuffer(b)); err == nil {
			t.Fatal("Expected error for bad status")
		}
	})
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(customResponseHandler(http.StatusCreated, TestStruct{A: "received"}))
		service := NewService(server.Client(), "", server.URL)
		b, _ := json.Marshal(TestStruct{A: "test test"})
		body, err := service.postJSON(service.url, bytes.NewBuffer(b))
		if err != nil {
			t.Fatal("Expected error for closed server")
		}
		var resObj TestStruct
		if err = json.NewDecoder(body).Decode(&resObj); err != nil {
			t.Fatal(err)
		}
		if resObj.A != "received" {
			t.Fatal("Unexpected response object")
		}
	})
}

func TestService_postScan(t *testing.T) {
	randomBytes := make([]byte, 100)
	rand.Read(randomBytes)

	t.Run("bad-reader", func(t *testing.T) {
		server := httptest.NewServer(customResponseHandler(http.StatusCreated, TestStruct{A: "received"}))
		service := NewService(server.Client(), "", server.URL)
		if err := service.postScan(badReader{}, Grype, engagement{}); err == nil {
			t.Fatal("Expected an error for a bad reader")
		}
	})

	t.Run("close-server", func(t *testing.T) {
		server := httptest.NewServer(nopHandler())
		server.Close()
		service := NewService(server.Client(), "", server.URL)
		if err := service.postScan(bytes.NewBuffer(randomBytes), Grype, engagement{}); err == nil {
			t.Fatal("Expected an error for a closed server")
		}
	})

	t.Run("bad-status", func(t *testing.T) {
		server := httptest.NewServer(badStatusHandler())
		service := NewService(server.Client(), "", server.URL)
		if err := service.postScan(bytes.NewBuffer(randomBytes), Grype, engagement{}); err == nil {
			t.Fatal("Expected an error for a bad server status")
		}
	})

	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(filePartHandler())
		service := NewService(server.Client(), "", server.URL)

		if err := service.postScan(bytes.NewBuffer(randomBytes), Grype, engagement{}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestService_productType(t *testing.T) {

	t.Run("existing", func(t *testing.T) {
		serverRes := paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}}

		server := httptest.NewServer(customResponseHandler(http.StatusOK, serverRes))
		service := NewService(server.Client(), "", server.URL)

		prodType, err := service.productType(EngagementQuery{ProductTypeName: "A"})
		if err != nil {
			t.Fatal(err)
		}

		if prodType.Id != 2 {
			t.Fatal("Expected id==2")
		}
	})

	t.Run("bad-query", func(t *testing.T) {
		server := httptest.NewServer(badStatusHandler())
		service := NewService(server.Client(), "", server.URL)

		if _, err := service.productType(EngagementQuery{}); err == nil {
			t.Fatal("Expected error for bad query")
		}
	})

	t.Run("bad-post", func(t *testing.T) {
		serverRes := paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}}

		server := httptest.NewServer(customResponseHandler(http.StatusOK, serverRes))
		service := NewService(server.Client(), "", server.URL)

		_, err := service.productType(EngagementQuery{Name: "B"})
		if err == nil {
			t.Fatal("expected error for bad post")
		}
	})

	t.Run("success", func(t *testing.T) {
		serverGETRes := paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}}
		serverPOSTRes := productType{Name: "B", Id: 3}
		server := httptest.NewServer(customRouteHandler(serverGETRes, serverPOSTRes))
		service := NewService(server.Client(), "", server.URL)

		prodType, err := service.productType(EngagementQuery{ProductTypeName: "B"})
		if err != nil {
			t.Fatal(err)
		}

		t.Log(prodType)
	})

}

func TestService_product(t *testing.T) {

	t.Run("existing", func(t *testing.T) {
		serverRes := paginatedResponse[product]{Results: []product{{Name: "A", Id: 2, ProdType: 5}}}

		server := httptest.NewServer(customResponseHandler(http.StatusOK, serverRes))
		service := NewService(server.Client(), "", server.URL)

		product, err := service.product(EngagementQuery{ProductName: "A"}, productType{Id: 5})
		if err != nil {
			t.Fatal(err)
		}

		if product.Id != 2 {
			t.Fatal("Expected id==2")
		}
	})

	t.Run("bad-query", func(t *testing.T) {
		server := httptest.NewServer(badStatusHandler())
		service := NewService(server.Client(), "", server.URL)

		if _, err := service.product(EngagementQuery{}, productType{Id: 5}); err == nil {
			t.Fatal("Expected error for bad query")
		}
	})

	t.Run("bad-post", func(t *testing.T) {
		serverRes := paginatedResponse[product]{Results: []product{{Name: "A", Id: 2}}}

		server := httptest.NewServer(customResponseHandler(http.StatusOK, serverRes))
		service := NewService(server.Client(), "", server.URL)

		_, err := service.product(EngagementQuery{Name: "B"}, productType{Id: 5})
		if err == nil {
			t.Fatal("expected error for bad post")
		}
	})

	t.Run("success", func(t *testing.T) {
		serverGETRes := paginatedResponse[product]{Results: []product{{Name: "A", Id: 2, ProdType: 6}}}
		serverPOSTRes := product{Name: "B", Id: 3, ProdType: 5}
		server := httptest.NewServer(customRouteHandler(serverGETRes, serverPOSTRes))
		service := NewService(server.Client(), "", server.URL)

		prodType, err := service.product(EngagementQuery{ProductName: "B"}, productType{Id: 5})
		if err != nil {
			t.Fatal(err)
		}

		t.Log(prodType)
	})
}

func TestService_engagement(t *testing.T) {

	t.Run("existing", func(t *testing.T) {
		serverRes := paginatedResponse[engagement]{Results: []engagement{{Name: "A", Id: 2, Product: 7}}}

		server := httptest.NewServer(customResponseHandler(http.StatusOK, serverRes))
		service := NewService(server.Client(), "", server.URL)

		eng, err := service.engagement(EngagementQuery{Name: "A"}, product{Id: 7})
		if err != nil {
			t.Fatal(err)
		}

		if eng.Id != 2 {
			t.Fatal("Expected id==2")
		}
	})

	t.Run("bad-query", func(t *testing.T) {
		server := httptest.NewServer(badStatusHandler())
		service := NewService(server.Client(), "", server.URL)

		if _, err := service.engagement(EngagementQuery{}, product{Id: 7}); err == nil {
			t.Fatal("Expected error for bad query")
		}
	})

	t.Run("bad-post", func(t *testing.T) {
		serverRes := paginatedResponse[engagement]{Results: []engagement{{Name: "A", Id: 2}}}

		server := httptest.NewServer(customResponseHandler(http.StatusOK, serverRes))
		service := NewService(server.Client(), "", server.URL)

		_, err := service.engagement(EngagementQuery{Name: "B"}, product{Id: 5})
		if err == nil {
			t.Fatal("expected error for bad post")
		}
	})

	t.Run("success", func(t *testing.T) {
		serverGETRes := paginatedResponse[engagement]{Results: []engagement{{Name: "A", Id: 2, Product: 6}}}
		serverPOSTRes := engagement{Name: "B", Id: 3, Product: 7}
		server := httptest.NewServer(customRouteHandler(serverGETRes, serverPOSTRes))
		service := NewService(server.Client(), "", server.URL)

		eng, err := service.engagement(EngagementQuery{ProductName: "B"}, product{Id: 7})
		if err != nil {
			t.Fatal(err)
		}

		t.Log(eng)
	})
}

func Test_export(t *testing.T) {
	t.Run("bad-productType", func(t *testing.T) {
		serverRes := paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}}
		server := httptest.NewServer(customResponseHandler(http.StatusOK, serverRes))
		service := NewService(server.Client(), "", server.URL)
		server.Close()
		if err := service.export(bytes.NewBufferString("a"), EngagementQuery{}, Grype); err == nil {
			t.Fatal("Expected error for bad product type query")
		}
	})

	t.Run("bad-product", func(t *testing.T) {
		routeTable := map[string]any{
			"/api/v2/product_types/": paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}},
		}

		server := httptest.NewServer(mapHandler(routeTable))
		service := NewService(server.Client(), "", server.URL)
		if err := service.export(bytes.NewBufferString("a"), EngagementQuery{ProductTypeName: "A"}, Grype); err == nil {
			t.Fatal("Expected error for bad product query")
		}
	})

	t.Run("bad-engagement", func(t *testing.T) {
		routeTable := map[string]any{
			"/api/v2/product_types/": paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}},
			"/api/v2/products/":      paginatedResponse[product]{Results: []product{{Name: "some product", Id: 5, ProdType: 2}}},
		}

		eq := EngagementQuery{ProductTypeName: "A", ProductName: "some product"}

		server := httptest.NewServer(mapHandler(routeTable))
		service := NewService(server.Client(), "", server.URL)
		if err := service.export(bytes.NewBufferString("a"), eq, Grype); err == nil {
			t.Fatal("Expected error for bad product query")
		}
	})

	t.Run("success", func(t *testing.T) {
		routeTable := map[string]any{
			"/api/v2/product_types/": paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}},
			"/api/v2/products/":      paginatedResponse[product]{Results: []product{{Name: "some product", Id: 5, ProdType: 2}}},
			"/api/v2/engagements/":   paginatedResponse[engagement]{Results: []engagement{{Name: "some engagement", Id: 7, Product: 5}}},
			"/api/v2/import-scan/":   TestStruct{A: "Good"},
		}

		eq := EngagementQuery{ProductTypeName: "A", ProductName: "some product", Name: "some engagement"}

		server := httptest.NewServer(mapHandler(routeTable))
		service := NewService(server.Client(), "", server.URL)
		if err := service.export(bytes.NewBufferString("a"), eq, Grype); err != nil {
			t.Fatal(err)
		}
	})
}

func TestService_Export(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		routeTable := map[string]any{
			"/api/v2/product_types/": paginatedResponse[productType]{Results: []productType{{Name: "A", Id: 2}}},
			"/api/v2/products/":      paginatedResponse[product]{Results: []product{{Name: "some product", Id: 5, ProdType: 2}}},
			"/api/v2/engagements/":   paginatedResponse[engagement]{Results: []engagement{{Name: "some engagement", Id: 7, Product: 5}}},
			"/api/v2/import-scan/":   TestStruct{A: "Good"},
		}

		eq := EngagementQuery{ProductTypeName: "A", ProductName: "some product", Name: "some engagement"}

		server := httptest.NewServer(mapHandler(routeTable))
		service := NewService(server.Client(), "", server.URL)
		if err := service.Export(context.Background(), bytes.NewBufferString("a"), eq, Grype); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("bad-server", func(t *testing.T) {

		eq := EngagementQuery{ProductTypeName: "A", ProductName: "some product", Name: "some engagement"}

		server := httptest.NewServer(nopHandler())
		service := NewService(server.Client(), "", server.URL)
		service.BackoffDuration = time.Nanosecond
		server.Close()
		if err := service.Export(context.Background(), bytes.NewBufferString("a"), eq, Grype); err == nil {
			t.Fatal("expected error for closed server")
		}
	})

	t.Run("time-out", func(t *testing.T) {

		server := httptest.NewServer(timeoutHandler())
		service := NewService(server.Client(), "", server.URL)

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*1)
		defer cancel()

		eq := EngagementQuery{ProductTypeName: "A", ProductName: "some product", Name: "some engagement"}
		if err := service.Export(ctx, bytes.NewBufferString("a"), eq, Grype); errors.Is(err, ctx.Err()) != true {
			t.Fatal(err)
		}
	})
}

type badReader struct{}

func (b badReader) Read(_ []byte) (_ int, err error) {
	return 0, errors.New("bad test reader")
}

type TestStruct struct {
	A string `json:"a"`
}

func badStatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func nopHandler() http.HandlerFunc {
	return func(_ http.ResponseWriter, _ *http.Request) {}
}

func customResponseHandler(statusCode int, returnObject any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(returnObject)
	}
}

func customRouteHandler(GETObjectRes any, POSTObjectRes any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(GETObjectRes)
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(POSTObjectRes)
		}
	}
}

func mapHandler(routeTable map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		item, ok := routeTable[r.RequestURI]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		}

		_ = json.NewEncoder(w).Encode(item)
	}
}

func customResponseWithNext(statusCode int, first any, second any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)

		switch r.RequestURI {
		case "/":
			_ = json.NewEncoder(w).Encode(&first)
		case "/second":
			_ = json.NewEncoder(w).Encode(&second)
		}
	}
}

func badDecodeHandler(statusCode int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = io.Copy(w, bytes.NewBufferString("{{"))
	}
}

func timeoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Minute * 30)
		w.WriteHeader(http.StatusRequestTimeout)
	}
}

func filePartHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const megabyte = int64(8 * 1_000 * 1_000)
		if err := r.ParseMultipartForm(megabyte * 10); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		fmt.Println(r.FormValue("engagement"))
		fmt.Println(r.FormValue("scan_type"))

		f, _, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		buf := new(bytes.Buffer)

		if _, err = io.Copy(buf, f); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if buf.Len() < 10 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func alwaysTrue[T any](_ T) bool {
	return true
}

func alwaysFalse[T any](_ T) bool {
	return false
}

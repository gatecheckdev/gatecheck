// Package defectdojo handles exporting reports to Defect Dojo open source software
package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"
)

// ErrAPI an error in the request
var ErrAPI = errors.New("defect dojo api request error")

// ScanType Defect Dojo specific scan type values
// Source for Scan Type Values https://demo.defectdojo.org/api/v2/doc/
type ScanType string

//	{
//		"id": 54,
//		"name": "CycloneDX Scan",
//		"static_tool": false,
//		"dynamic_tool": false,
//		"active": true
//	  },
const (
	Grype     ScanType = "Anchore Grype"
	CycloneDX ScanType = "CycloneDX Scan"
	Semgrep   ScanType = "Semgrep JSON Report"
	Gitleaks  ScanType = "Gitleaks Scan"
)

const contentTypeJSON = "application/json"

// EngagementQuery data model for request
type EngagementQuery struct {
	ProductTypeName            string
	ProductName                string
	Name                       string
	Duration                   time.Duration
	BranchTag                  string
	SourceURL                  string
	CommitHash                 string
	Tags                       []string
	DeduplicationOnEngagement  bool
	EnableSimpleRiskAcceptance bool
}

// Service can be used to export scans to Defect Dojo
type Service struct {
	Retry                             int       // How many times to retry on a failed export
	DescriptionTime                   time.Time // The time zone used when auto generating the description
	DescriptionTimezone               string
	BackoffDuration                   time.Duration // The interval for the exponential back off retry
	client                            *http.Client
	key                               string
	url                               string
	CloseOldFindings                  bool
	CloseOldFindingsProductScope      bool
	CreateFindingGroupsForAllFindings bool
	ImportScanActive                  bool
	ImportScanVerified                bool
	GroupBy                           string
	log                               *slog.Logger
}

// NewService customize fields for each future query
func NewService(client *http.Client, key string, url string, closeOldFindings bool, closeOldFindingsProductScope bool, createFindingGroupsForAllFindings bool, importScanActive bool, importScanVerified bool, groupBy string) Service {
	return Service{
		client:                            client,
		key:                               key,
		url:                               url,
		CloseOldFindings:                  closeOldFindings,
		CloseOldFindingsProductScope:      closeOldFindingsProductScope,
		CreateFindingGroupsForAllFindings: createFindingGroupsForAllFindings,
		ImportScanActive:                  importScanActive,
		ImportScanVerified:                importScanVerified,
		GroupBy:                           groupBy,
		DescriptionTime:                   time.Now(),
		Retry:                             3,
		BackoffDuration:                   time.Second,
		log:                               slog.Default().With("export_service", "defect_dojo", "url", url),
	}
}

// Export execute export request
func (s Service) Export(ctx context.Context, r io.Reader, e EngagementQuery, scanType ScanType) error {
	c := make(chan struct {
		attempt int
		errs    error
	})

	go func() {
		result := struct {
			attempt int
			errs    error
		}{}

		for i := 0; i < s.Retry; i++ {
			result.attempt++
			err := s.export(r, e, scanType)
			result.errs = errors.Join(result.errs, err)

			if err != nil {
				// Sleep for 2 ^ backoff, seconds
				sleepFor := time.Duration(int64(math.Pow(2, float64(i)))) * s.BackoffDuration
				slog.Warn("export", "attempt", result.attempt, "err", err, "retry_after", sleepFor.String())
				time.Sleep(sleepFor)
				continue
			}
			c <- result
			break
		} // end for
		c <- result
	}()

	for {
		select {
		case result := <-c:
			if result.errs == nil {
				return nil
			}
			slog.Error("all attempts failed", "result", result)
			return result.errs
		case <-ctx.Done():
			slog.Warn("context cancelled")
			return ctx.Err()
		}
	}
}

func (s Service) export(r io.Reader, e EngagementQuery, scanType ScanType) error {
	prodType, err := s.productType(e)
	if err != nil {
		return err
	}

	prod, err := s.product(e, prodType)
	if err != nil {
		return err
	}

	eng, err := s.engagement(e, prod)
	if err != nil {
		return err
	}

	return s.postScan(r, scanType, eng)
}

func (s Service) productType(e EngagementQuery) (productType, error) {
	url := s.url + "/api/v2/product_types/"
	log := s.log.With("url", url)
	log.Debug("product type request", "query", e)

	returnedProductType, err := query[productType](s.client, s.key, url, func(p productType) bool {
		return p.Name == e.ProductTypeName
	})

	switch {
	case err == nil:
		return returnedProductType, nil
	case err == errNotFound:
		log.Debug("not found, will create")
		break
	case err != nil:
		log.Error("", "err", err)
		return productType{}, err
	}

	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(productType{Name: e.ProductTypeName, Description: s.description()})

	resBody, err := s.postJSON(url, buf)

	if err != nil {
		return productType{}, err
	}

	newProductType := productType{}
	err = json.NewDecoder(resBody).Decode(&newProductType)

	return newProductType, err
}

func (s Service) product(e EngagementQuery, prodType productType) (product, error) {
	url := s.url + "/api/v2/products/"
	log := s.log.With("url", url, "product_type", prodType, "product", e.ProductName)
	log.Debug("product request", "query", e)

	returnedProduct, err := query[product](s.client, s.key, url, func(givenProduct product) bool {
		productTypeMatches := givenProduct.ProdType == prodType.ID
		productNameMatches := givenProduct.Name == e.ProductName
		return productTypeMatches && productNameMatches
	})

	switch {
	case err == nil:
		return returnedProduct, nil
	case err == errNotFound:
		log.Debug("product not found, will create")
		break
	case err != nil:
		log.Error("fail to get product", "err", err)
		return product{}, err
	}

	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(product{
		Name:                       e.ProductName,
		Description:                s.description(),
		ProdType:                   prodType.ID,
		EnableSimpleRiskAcceptance: e.EnableSimpleRiskAcceptance,
	})

	resBody, err := s.postJSON(url, buf)
	if err != nil {
		return product{}, err
	}

	newProduct := product{}
	err = json.NewDecoder(resBody).Decode(&newProduct)

	return newProduct, err
}

func (s Service) engagement(e EngagementQuery, prod product) (engagement, error) {

	url := s.url + "/api/v2/engagements/"

	log := s.log.With("url", url, "product_type", e.ProductTypeName, "product", e.ProductName)
	log.Debug("egagement request", "query", e)

	var queryFunction = func(givenEngagement engagement) bool {
		productMatches := givenEngagement.Product == prod.ID
		engagementNameMatches := givenEngagement.Name == e.Name
		return productMatches && engagementNameMatches
	}

	returnedEngagement, err := query[engagement](s.client, s.key, url, queryFunction)

	if err == nil {
		return returnedEngagement, err
	}

	if !errors.Is(err, errNotFound) {
		return engagement{}, err
	}

	loc, _ := time.LoadLocation("EST")

	buf := new(bytes.Buffer)
	newEngagement := &engagement{
		Name: e.Name, Description: s.description(),
		TargetStart: time.Now().In(loc).Format("2006-01-02"),
		TargetEnd:   time.Now().In(loc).Add(e.Duration).Format("2006-01-02"),
		Product:     prod.ID, Active: true, Status: "In Progress", EngagementType: "CI/CD", CommitHash: e.CommitHash,
		BranchTag: e.BranchTag, SourceCodeManagementURI: e.SourceURL,
		Tags: e.Tags,
	}
	_ = json.NewEncoder(buf).Encode(newEngagement)

	resBody, err := s.postJSON(url, buf)
	if err != nil {
		return engagement{}, err
	}
	var resEngagement engagement

	err = json.NewDecoder(resBody).Decode(&resEngagement)
	return resEngagement, err
}

func (s Service) postScan(r io.Reader, scanType ScanType, e engagement) error {
	url := s.url + "/api/v2/import-scan/"
	// After getting an engagement, post the scan using a multipart form
	log := s.log.With("url", url, "scan_type", scanType)
	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)
	_ = writer.WriteField("engagement", strconv.Itoa(e.ID))
	_ = writer.WriteField("scan_type", string(scanType))
	_ = writer.WriteField("deduplication_on_engagement", strconv.FormatBool(e.DeduplicationOnEngagement))
	_ = writer.WriteField("close_old_findings", strconv.FormatBool(s.CloseOldFindings))
	_ = writer.WriteField("close_old_findings_product_scope", strconv.FormatBool(s.CloseOldFindingsProductScope))
	_ = writer.WriteField("create_finding_groups_for_all_findings", strconv.FormatBool(s.CreateFindingGroupsForAllFindings))
	_ = writer.WriteField("active", strconv.FormatBool(s.ImportScanActive))
	_ = writer.WriteField("verified", strconv.FormatBool(s.ImportScanVerified))
	_ = writer.WriteField("group_by", string("component_name+component_version"))

	// Leave error checking to io.Copy and just log for debugging purposes, error unlikely to occur
	filePart, createFormErr := writer.CreateFormFile("file", fmt.Sprintf("%s report.json", scanType))

	// Copy the file content to the filePart
	if _, err := io.Copy(filePart, r); err != nil {
		log.Error("failed io.copy to file part", "err", err, "create_form_err", createFormErr)
		return fmt.Errorf("defect dojo service can't write file to form %w", err)
	}

	contentType := writer.FormDataContentType()
	_ = writer.Close()

	req, newReqErr := http.NewRequest(http.MethodPost, url, payload)

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.key))

	res, err := s.client.Do(req)

	if err != nil {
		log.Error("request", "err", err, "newReqErr", newReqErr)
		return err
	}

	if res.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%w: POST '%s' unexpected response code %d msg: %s",
			ErrAPI, url, res.StatusCode, string(msg))
	}

	return nil
}

func (s Service) postJSON(url string, reqBody io.Reader) (resBody io.ReadCloser, err error) {
	// just log this error because it's unlikely and would fail client anyway since Do check for nil
	log := s.log.With("url", url)
	req, newReqErr := http.NewRequest(http.MethodPost, url, reqBody)
	req.Header.Set("Content-Type", contentTypeJSON)
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.key))

	res, err := s.client.Do(req)

	if err != nil {
		s.log.Error("failed request", "err", err, "url", url, "new_req_err", newReqErr)
		return nil, err
	}

	if res.StatusCode != http.StatusCreated {
		msg, readErr := io.ReadAll(res.Body)
		log.Error("non 201 response", "url", url, "msg", string(msg), "read_body_err", readErr)
		return nil, fmt.Errorf("%w: GET '%s' unexpected response code %d: msg: %s",
			ErrAPI, url, res.StatusCode, string(msg))
	}
	return res.Body, nil
}

func (s Service) description() string {
	timeStamp := s.DescriptionTime.Format("02 January 2006, 15:04")
	return fmt.Sprintf("Auto-generated by Gatecheck %s %s", timeStamp, s.DescriptionTimezone)
}

var errNotFound = errors.New("no results found")

// query will perform the query and use the queryFunc to determine a match, parsing through paginated responses
func query[T any](client *http.Client, key string, url string, queryFunc func(T) bool) (T, error) {
	log := slog.Default().With("func", "query", "url", url)
	next := url

	for next != "" {
		req, newReqErr := http.NewRequest(http.MethodGet, next, nil)
		req.Header.Set("Authorization", fmt.Sprintf("Token %s", key))

		res, err := client.Do(req)

		if err != nil {
			log.Error("failed query", "err", err, "new_req_err", newReqErr)
			return *new(T), err
		}

		if res.StatusCode != http.StatusOK {
			msg, readErr := io.ReadAll(res.Body)
			log.Error("non 200 response", "url", url, "msg", string(msg), "read_body_err", readErr)

			return *new(T), fmt.Errorf("%w: GET '%s' unexpected response code %d msg: %s",
				ErrAPI, next, res.StatusCode, string(msg))
		}

		var response paginatedResponse[T]
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return *new(T), fmt.Errorf("%w: %v", ErrAPI, err)
		}

		for _, v := range response.Results {
			if queryFunc(v) {
				return v, nil
			}
		}
		next = response.Next
	}
	return *new(T), errNotFound
}

package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"
)

var RequestError = errors.New("defect dojo request error")

type ScanType string

// Source for Scan Type Values https://demo.defectdojo.org/api/v2/doc/

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
}

func NewService(client *http.Client, key string, url string, closeOldFindings bool, closeOldFindingsProductScope bool, createFindingGroupsForAllFindings bool) Service {
	return Service{
		client:                            client,
		key:                               key,
		url:                               url,
		CloseOldFindings:                  closeOldFindings,
		CloseOldFindingsProductScope:      closeOldFindingsProductScope,
		CreateFindingGroupsForAllFindings: createFindingGroupsForAllFindings,
		DescriptionTime:                   time.Now(),
		Retry:                             3,
		BackoffDuration:                   time.Second,
	}
}

func (s Service) Export(ctx context.Context, r io.Reader, e EngagementQuery, scanType ScanType) error {
	c := make(chan error)

	go func() {
		var err error
		for i := 0; i < s.Retry; i++ {
			err = s.export(r, e, scanType)
			if err == nil {
				close(c)
				return
			}
			// Sleep for 2 ^ backoff, seconds
			sleepFor := time.Duration(int64(math.Pow(2, float64(i)))) * s.BackoffDuration
			log.Printf("Export Attempt %d / %d, will Retrying after %s. Error: %v\n", i+1, s.Retry,
				sleepFor.String(), err)
			time.Sleep(sleepFor)
		}
		c <- err
	}()

	for {
		select {
		case err, ok := <-c:
			if !ok {
				return nil
			}
			return err
		case <-ctx.Done():
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

	var queryFunction = func(givenProductType productType) bool {
		productTypeNameMatches := givenProductType.Name == e.ProductTypeName
		return productTypeNameMatches
	}

	returnedProductType, err := query[productType](s.client, s.key, url, queryFunction)

	if err == nil {
		return returnedProductType, err
	}

	if errors.Is(err, errNotFound) == false {
		return productType{}, err
	}

	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(productType{Name: e.ProductTypeName,
		Description: s.description()})

	resBody, err := s.postJSON(url, buf)
	if err != nil {
		return productType{}, err
	}
	var newProductType productType
	err = json.NewDecoder(resBody).Decode(&newProductType)

	return newProductType, err
}

func (s Service) product(e EngagementQuery, prodType productType) (product, error) {
	url := s.url + "/api/v2/products/"

	var queryFunction = func(givenProduct product) bool {
		productTypeMatches := givenProduct.ProdType == prodType.Id
		productNameMatches := givenProduct.Name == e.ProductName
		return productTypeMatches && productNameMatches
	}

	returnedProduct, err := query[product](s.client, s.key, url, queryFunction)

	if err == nil {
		return returnedProduct, err
	}

	if errors.Is(err, errNotFound) == false {
		return product{}, err
	}

	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(product{
		Name:                       e.ProductName,
		Description:                s.description(),
		ProdType:                   prodType.Id,
		EnableSimpleRiskAcceptance: e.EnableSimpleRiskAcceptance,
	})

	resBody, err := s.postJSON(url, buf)
	if err != nil {
		return product{}, err
	}
	var newProduct product
	err = json.NewDecoder(resBody).Decode(&newProduct)

	return newProduct, err
}

func (s Service) engagement(e EngagementQuery, prod product) (engagement, error) {

	url := s.url + "/api/v2/engagements/"

	var queryFunction = func(givenEngagement engagement) bool {
		productMatches := givenEngagement.Product == prod.Id
		engagementNameMatches := givenEngagement.Name == e.Name
		return productMatches && engagementNameMatches
	}

	returnedEngagement, err := query[engagement](s.client, s.key, url, queryFunction)

	if err == nil {
		return returnedEngagement, err
	}

	if errors.Is(err, errNotFound) == false {
		return engagement{}, err
	}

	loc, _ := time.LoadLocation("EST")

	buf := new(bytes.Buffer)
	newEngagement := &engagement{
		Name: e.Name, Description: s.description(),
		TargetStart: time.Now().In(loc).Format("2006-01-02"),
		TargetEnd:   time.Now().In(loc).Add(e.Duration).Format("2006-01-02"),
		Product:     prod.Id, Active: true, Status: "In Progress", EngagementType: "CI/CD", CommitHash: e.CommitHash,
		BranchTag: e.BranchTag, SourceCodeManagementUri: e.SourceURL,
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
	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)
	_ = writer.WriteField("engagement", strconv.Itoa(e.Id))
	_ = writer.WriteField("scan_type", string(scanType))
	_ = writer.WriteField("deduplication_on_engagement", strconv.FormatBool(e.DeduplicationOnEngagement))
	_ = writer.WriteField("close_old_findings", strconv.FormatBool(s.CloseOldFindings))
	_ = writer.WriteField("close_old_findings_product_scope", strconv.FormatBool(s.CloseOldFindingsProductScope))
	_ = writer.WriteField("create_finding_groups_for_all_findings", strconv.FormatBool(s.CreateFindingGroupsForAllFindings))

	filePart, _ := writer.CreateFormFile("file", fmt.Sprintf("%s report.json", scanType))

	// Copy the file content to the filePart
	if _, err := io.Copy(filePart, r); err != nil {
		return fmt.Errorf("Defect Dojo, can't write file to form %w\n", err)
	}

	contentType := writer.FormDataContentType()
	_ = writer.Close()

	req, _ := http.NewRequest(http.MethodPost, url, payload)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.key))

	res, err := s.client.Do(req)

	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%w: POST '%s' unexpected response code %d msg: %s",
			RequestError, url, res.StatusCode, msg)
	}

	return nil
}

func (s Service) postJSON(url string, reqBody io.Reader) (resBody io.ReadCloser, err error) {
	req, _ := http.NewRequest(http.MethodPost, url, reqBody)
	req.Header.Set("Content-Type", contentTypeJSON)
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.key))

	res, err := s.client.Do(req)

	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("%w: GET '%s' unexpected response code %d: msg: %s",
			RequestError, url, res.StatusCode, string(msg))
	}
	return res.Body, nil
}

func (s Service) description() string {
	timeStamp := s.DescriptionTime.Format("02 January 2006, 15:04")

	return fmt.Sprintf("Auto-generated by Gatecheck %s %s", timeStamp, s.DescriptionTimezone)
}

var errNotFound = errors.New("no results found")

func query[T any](client *http.Client, key string, url string, queryFunc func(T) bool) (T, error) {

	next := url

	for next != "" {
		req, _ := http.NewRequest(http.MethodGet, next, nil)
		req.Header.Set("Authorization", fmt.Sprintf("Token %s", key))

		res, err := client.Do(req)

		if err != nil {
			return *new(T), err
		}

		if res.StatusCode != http.StatusOK {
			msg, _ := io.ReadAll(res.Body)
			return *new(T), fmt.Errorf("%w: GET '%s' unexpected response code %d msg: %s",
				RequestError, next, res.StatusCode, msg)
		}

		var response paginatedResponse[T]
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return *new(T), fmt.Errorf("%w: %v", RequestError, err)
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

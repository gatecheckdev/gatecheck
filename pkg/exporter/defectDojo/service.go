package defectDojo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/exporter/defectDojo/models"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"strconv"
)

type ProductTypeHandler interface {
	GetProductTypes() ([]models.ProductType, error)
	PostProductType(models.ProductType) (*models.ProductType, error)
}

type ProductHandler interface {
	GetProducts() ([]models.Product, error)
	PostProduct(models.Product) (*models.Product, error)
}

type EngagementHandler interface {
	GetEngagements() ([]models.Engagement, error)
	GetEngagementsByProduct(productID int) ([]models.Engagement, error)
	PostEngagement(models.Engagement) (*models.Engagement, error)
}

type ScanHandler interface {
	PostScan(io.Reader, int, ScanType) (*models.ScanImportResponse, error)
}

type ScanType string

const (
	Grype ScanType = "Anchore Grype"
)

type Service interface {
	ProductTypeHandler
	ProductHandler
	EngagementHandler
	ScanHandler
}

type APIClient struct {
	client *http.Client
	key    string
	url    string
}

func (c APIClient) GetEngagements() ([]models.Engagement, error) {
	return get[models.Engagement](c, c.url+"/api/v2/engagements/")
}

func (c APIClient) GetEngagementsByProduct(productID int) ([]models.Engagement, error) {
	return get[models.Engagement](c, fmt.Sprintf("%s/api/v2/engagements/?product=%d", c.url, productID))
}

func (c APIClient) PostEngagement(engagement models.Engagement) (*models.Engagement, error) {
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(engagement)
	return post[models.Engagement](c, buf, "application/json", c.url+"/api/v2/engagements/")
}

func (c APIClient) GetProductTypes() ([]models.ProductType, error) {
	return get[models.ProductType](c, c.url+"/api/v2/product_types/")
}

func (c APIClient) PostProductType(productType models.ProductType) (*models.ProductType, error) {
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(productType)
	return post[models.ProductType](c, buf, "application/json", c.url+"/api/v2/product_types/")
}

func (c APIClient) GetProducts() ([]models.Product, error) {
	return get[models.Product](c, c.url+"/api/v2/products/")
}

func (c APIClient) PostProduct(p models.Product) (*models.Product, error) {
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(p)
	return post[models.Product](c, buf, "application/json", c.url+"/api/v2/products/")
}

func (c APIClient) PostScan(r io.Reader, engagementID int, scanType ScanType) (*models.ScanImportResponse, error) {
	payload := &bytes.Buffer{}

	// Write the file to the form writer
	writer := multipart.NewWriter(payload)
	_ = writer.WriteField("engagement", strconv.Itoa(engagementID))
	_ = writer.WriteField("scan_type", string(scanType))

	filePart, _ := writer.CreateFormFile("file", fmt.Sprintf("%s report.json", string(scanType)))

	// Copy the file content to the filePart
	if _, err := io.Copy(filePart, r); err != nil {
		return nil, fmt.Errorf("Defect Dojo, can't write file to form %w\n", err)
	}
	contentType := writer.FormDataContentType()
	_ = writer.Close()

	return post[models.ScanImportResponse](c, payload, contentType, c.url+"/api/v2/import-scan/")
}

// Helper Functions

func getPaginatedResponse(api APIClient, url string) (*models.PaginatedResponse, error) {
	response := new(models.PaginatedResponse)

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", api.key))

	// Execute the Request
	res, err := api.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Defect Dojo GET APIClient request failed '%s': %w\n", url, err)
	}

	// Check if the Request succeeded in create the object
	if res.StatusCode != http.StatusOK {
		log.Printf("Status Code: %d\n", res.StatusCode)
		return nil, fmt.Errorf("Defect Dojo GET APIClient unexpected response code %d route: '%s'\n",
			res.StatusCode, url)
	}

	// Decode the JSON Response
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("Defect Dojo GET APIClient failed to decode response '%s': %w\n", url, err)
	}

	return response, nil
}

// castByEncoding takes a slice of any type and 'converts' it to a concrete type by encoding into a json string and
// decoding into a given object type.
func castByEncoding[objectType any](results []interface{}) ([]objectType, error) {
	objects := make([]objectType, len(results))
	for i, result := range results {
		// Encode the result which is a map[string]interface{} into a string
		buf := new(bytes.Buffer)
		if err := json.NewEncoder(buf).Encode(result); err != nil {
			return nil, err
		}
		// Decode the string into the appropriate object
		object := new(objectType)
		if err := json.NewDecoder(buf).Decode(object); err != nil {
			return nil, err
		}
		objects[i] = *object
	}
	return objects, nil
}

// Templates

func get[objectType any](api APIClient, url string) ([]objectType, error) {
	var objects []objectType
	next := url

	// Loop until there is no next url
	for next != "" {
		response, err := getPaginatedResponse(api, next)
		if err != nil {
			return nil, err
		}
		next = response.Next

		extractedObjects, err := castByEncoding[objectType](response.Results)
		if err != nil {
			return nil, err
		}
		objects = append(objects, extractedObjects...)
	}

	return objects, nil
}

func post[objectType any](api APIClient, r io.Reader, contentType string, url string) (*objectType, error) {
	resObject := new(objectType)

	// Create the Request POST object
	req, _ := http.NewRequest(http.MethodPost, url, r)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", api.key))

	// Execute the Request
	res, err := api.client.Do(req)
	if err != nil {
		return resObject, fmt.Errorf("Defect Dojo Post Service failed request execution '%s': %w\n", url, err)
	}

	// Check if the Request succeeded in create the object
	if res.StatusCode != http.StatusCreated {
		log.Printf("Status Code: %d\n", res.StatusCode)
		_, _ = io.Copy(log.Writer(), res.Body)
		return resObject, fmt.Errorf("Defect Dojo Post Service unexpected response code %d route: '%s'\n",
			res.StatusCode, url)
	}

	// Decode the returned response
	if err := json.NewDecoder(res.Body).Decode(&resObject); err != nil {
		return resObject, fmt.Errorf("Defect Dojo Post Service failed to parse response '%s': %w\n", url, err)
	}

	// Return the Response object
	return resObject, nil
}

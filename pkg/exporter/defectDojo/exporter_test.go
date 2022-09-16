package defectDojo

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/pkg/exporter/defectDojo/models"
	"io"
	"testing"
)

func TestExporter_ExportGrype(t *testing.T) {
	errExpected := errors.New("mocked error")

	e := NewExporter(Config{ProductTypeName: "prod type 1", ProductName: "prod 1", EngagementName: "engagement 1"})

	service := mockService{
		errProductType: errExpected, getProductTypeValue: []models.ProductType{{Id: 1, Name: "prod type 1"}},
		errProduct: errExpected, getProductValue: []models.Product{{Id: 1, ProdType: 1, Name: "prod 1"}},
		errEngagement: errExpected, getEngagementValue: []models.Engagement{{Id: 1, Name: "engagement 1", Product: 1}},
	}

	if err := e.WithService(service).ExportGrype(new(bytes.Buffer)); err == nil {
		t.Fatal("Expected to fail getting product Type")
	}
	// turn off product type error
	service.errProductType = nil
	if err := e.WithService(service).ExportGrype(new(bytes.Buffer)); err == nil {
		t.Fatal("Expected to fail getting product")
	}

	// turn off product error
	service.errProduct = nil
	if err := e.WithService(service).ExportGrype(new(bytes.Buffer)); err == nil {
		t.Fatal("Expected to fail getting engagement")
	}

	// turn off engagement error, Provoke encode error
	service.errEngagement = nil
	if err := e.WithService(service).ExportGrype(bytes.NewBufferString("Some scan data")); err != nil {
		t.Fatal(err)
	}
}

func TestExporter_getProductType(t *testing.T) {
	service := mockService{errProductType: errors.New("server down")}
	e := NewExporter(Config{}).WithService(service)
	_, err := e.getProductType("")
	if err == nil {
		t.Fatal("Expected error for bad service")
	}

	service = mockService{getProductTypeValue: []models.ProductType{
		{Name: "some", Id: 1},
		{Name: "prod type", Id: 2},
		{Name: "some prod type", Id: 3},
	}}

	productType, _ := e.WithService(service).getProductType("prod type")
	if productType.Id != 2 {
		t.Fatal("Expected ID 2")
	}

	service = mockService{postProductTypeValue: &models.ProductType{Id: 4}}
	// provoke post
	productType, err = e.WithService(service).getProductType("new prod type")
	if err != nil {
		t.Fatal(err)
	}
	if productType.Id != 4 {
		t.Fatal("Expected ID 4")
	}
}

func TestExporter_getProduct(t *testing.T) {
	service := mockService{errProduct: errors.New("server down")}
	e := NewExporter(Config{}).WithService(service)

	if _, err := e.getProduct(0, ""); err == nil {
		t.Fatal("Expected error for bad service")
	}

	service = mockService{getProductValue: []models.Product{
		{Name: "some", Id: 1, ProdType: 2},
		{Name: "product", Id: 2, ProdType: 1},
		{Name: "some product 1", Id: 3, ProdType: 1},
	}}

	product, _ := e.WithService(service).getProduct(1, "some product 1")
	if product.Id != 3 {
		t.Fatal("Expected ID 3")
	}

	service = mockService{postProductValue: &models.Product{Id: 4, ProdType: 1}}
	// provoke post
	product, err := e.WithService(service).getProduct(1, "new product")
	if err != nil {
		t.Fatal(err)
	}
	if product.Id != 4 {
		t.Fatal("Expected ID 4")
	}
}

func TestExporter_getEngagement(t *testing.T) {
	service := mockService{errEngagement: errors.New("server down")}
	e := Exporter{service: service}
	_, err := e.WithService(service).getEngagement(0, "")
	if err == nil {
		t.Fatal("Expected error for bad service")
	}

	service = mockService{getEngagementValue: []models.Engagement{
		{Name: "some", Id: 1, Product: 2},
		{Name: "engagement", Id: 2, Product: 1},
		{Name: "some engagement 1", Id: 3, Product: 1},
	}}

	product, _ := e.WithService(service).getEngagement(1, "some engagement 1")
	if product.Id != 3 {
		t.Fatal("Expected ID 3")
	}

	service = mockService{postEngagementValue: &models.Engagement{Id: 4, Product: 1}}
	// provoke post
	product, err = e.WithService(service).getEngagement(1, "new engagement")
	if err != nil {
		t.Fatal(err)
	}
	if product.Id != 4 {
		t.Fatal("Expected ID 4")
	}
}

type mockService struct {
	errProductType       error
	getProductTypeValue  []models.ProductType
	postProductTypeValue *models.ProductType
	errProduct           error
	getProductValue      []models.Product
	postProductValue     *models.Product
	errEngagement        error
	getEngagementValue   []models.Engagement
	postEngagementValue  *models.Engagement
	postScanValue        *models.ScanImportResponse
	errScan              error
}

func (m mockService) PostScan(reader io.Reader, i int, scanType ScanType) (*models.ScanImportResponse, error) {
	return m.postScanValue, m.errScan
}

func (m mockService) GetProductTypes() ([]models.ProductType, error) {
	return m.getProductTypeValue, m.errProductType
}

func (m mockService) PostProductType(productType models.ProductType) (*models.ProductType, error) {
	return m.postProductTypeValue, m.errProductType
}

func (m mockService) GetProducts() ([]models.Product, error) {
	return m.getProductValue, m.errProduct
}

func (m mockService) PostProduct(product models.Product) (*models.Product, error) {
	return m.postProductValue, m.errProduct
}

func (m mockService) GetEngagements() ([]models.Engagement, error) {
	panic("implement me")
}

func (m mockService) GetEngagementsByProduct(_ int) ([]models.Engagement, error) {
	return m.getEngagementValue, m.errEngagement
}

func (m mockService) PostEngagement(engagement models.Engagement) (*models.Engagement, error) {
	return m.postEngagementValue, m.errEngagement
}

package entity

import "time"

/*
Cyber Infrastructure and Security Agency (CISA) Known Exploited Vulnerabilities

CISA maintains the authoritative source of vulnerabilities that have been exploited in the
wild: the Known Exploited Vulnerability (KEV) catalog. CISA strongly recommends all organizations review and monitor
the KEV catalog and prioritize remediation of the listed vulnerabilities to reduce the
likelihood of compromise by known threat actors.
*/

type KEVCatalog struct {
	Title           string                    `json:"title"`
	CatalogVersion  string                    `json:"catalogVersion"`
	DateReleased    time.Time                 `json:"dateReleased"`
	Count           int                       `json:"count"`
	Vulnerabilities []KEVCatalogVulnerability `json:"vulnerabilities"`
}

type KEVCatalogVulnerability struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
}
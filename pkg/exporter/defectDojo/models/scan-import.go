package models

type ScanImportResponse struct {
	ScanDate                  string               `json:"scan_date"`
	MinimumSeverity           string               `json:"minimum_severity"`
	Active                    bool                 `json:"active"`
	Verified                  bool                 `json:"verified"`
	ScanType                  string               `json:"scan_type"`
	EndpointToAdd             int                  `json:"endpoint_to_add"`
	File                      string               `json:"file"`
	ProductTypeName           string               `json:"product_type_name"`
	ProductName               string               `json:"product_name"`
	EngagementName            string               `json:"engagement_name"`
	Engagement                int                  `json:"engagement"`
	TestTitle                 string               `json:"test_title"`
	AutoCreateContext         bool                 `json:"auto_create_context"`
	DeduplicationOnEngagement bool                 `json:"deduplication_on_engagement"`
	Lead                      int                  `json:"lead"`
	Tags                      []string             `json:"tags"`
	CloseOldFindings          bool                 `json:"close_old_findings"`
	PushToJira                bool                 `json:"push_to_jira"`
	Environment               string               `json:"environment"`
	Version                   string               `json:"version"`
	BuildId                   string               `json:"build_id"`
	BranchTag                 string               `json:"branch_tag"`
	CommitHash                string               `json:"commit_hash"`
	ApiScanConfiguration      int                  `json:"api_scan_configuration"`
	Service                   string               `json:"service"`
	GroupBy                   string               `json:"group_by"`
	Test                      int                  `json:"test"`
	TestId                    int                  `json:"test_id"`
	EngagementId              int                  `json:"engagement_id"`
	ProductId                 int                  `json:"product_id"`
	ProductTypeId             int                  `json:"product_type_id"`
	Statistics                defectDojoStatistics `json:"statistics"`
}

type defectDojoStatistics struct {
	Before defectDojoVulnerabilityGroup `json:"before"`
	Delta  defectDojoVulnerabilityGroup `json:"delta"`
	After  defectDojoVulnerabilityGroup `json:"after"`
}

type defectDojoVulnerabilityGroup struct {
	Info     defectDojoVulnerability `json:"info"`
	Low      defectDojoVulnerability `json:"low"`
	Medium   defectDojoVulnerability `json:"medium"`
	High     defectDojoVulnerability `json:"high"`
	Critical defectDojoVulnerability `json:"critical"`
	Total    defectDojoVulnerability `json:"total"`
}

type defectDojoVulnerability struct {
	Active       int `json:"active"`
	Verified     int `json:"verified"`
	Duplicate    int `json:"duplicate"`
	FalseP       int `json:"false_p"`
	OutOfScope   int `json:"out_of_scope"`
	IsMitigated  int `json:"is_mitigated"`
	RiskAccepted int `json:"risk_accepted"`
	Total        int `json:"total"`
}

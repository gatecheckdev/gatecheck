package defectdojo

import "time"

type paginatedResponse[T any] struct {
	Count    int    `json:"count"`
	Next     string `json:"next"`
	Previous string `json:"previous"`
	Results  []T    `json:"results"`
}
type paginatedResponseOld struct {
	Count    int           `json:"count"`
	Next     string        `json:"next"`
	Previous string        `json:"previous"`
	Results  []interface{} `json:"results"`
}

type engagement struct {
	Id                         int       `json:"id,omitempty"`
	Tags                       []string  `json:"tags,omitempty"`
	Name                       string    `json:"name,omitempty"`
	Description                string    `json:"description,omitempty"`
	Version                    string    `json:"version,omitempty"`
	FirstContacted             string    `json:"first_contacted,omitempty"`
	TargetStart                string    `json:"target_start,omitempty"`
	TargetEnd                  string    `json:"target_end,omitempty"`
	Reason                     string    `json:"reason,omitempty"`
	Updated                    time.Time `json:"updated,omitempty"`
	Created                    time.Time `json:"created,omitempty"`
	Active                     bool      `json:"active,omitempty"`
	Tracker                    string    `json:"tracker,omitempty"`
	TestStrategy               string    `json:"test_strategy,omitempty"`
	ThreatModel                bool      `json:"threat_model,omitempty"`
	ApiTest                    bool      `json:"api_test,omitempty"`
	PenTest                    bool      `json:"pen_test,omitempty"`
	CheckList                  bool      `json:"check_list,omitempty"`
	Status                     string    `json:"status,omitempty"`
	Progress                   string    `json:"progress,omitempty"`
	TmodelPath                 string    `json:"tmodel_path,omitempty"`
	DoneTesting                bool      `json:"done_testing,omitempty"`
	EngagementType             string    `json:"engagement_type,omitempty"`
	BuildId                    string    `json:"build_id,omitempty"`
	CommitHash                 string    `json:"commit_hash,omitempty"`
	BranchTag                  string    `json:"branch_tag,omitempty"`
	SourceCodeManagementUri    string    `json:"source_code_management_uri,omitempty"`
	DeduplicationOnEngagement  bool      `json:"deduplication_on_engagement,omitempty"`
	Lead                       int       `json:"lead,omitempty"`
	Requester                  int       `json:"requester,omitempty"`
	Preset                     int       `json:"preset,omitempty"`
	ReportType                 int       `json:"report_type,omitempty"`
	Product                    int       `json:"product,omitempty"`
	BuildServer                int       `json:"build_server,omitempty"`
	SourceCodeManagementServer int       `json:"source_code_management_server,omitempty"`
	OrchestrationEngine        int       `json:"orchestration_engine,omitempty"`
	Notes                      []struct {
		Id      int  `json:"id,omitempty"`
		Author  user `json:"author,omitempty"`
		Editor  user `json:"editor,omitempty"`
		History []struct {
			Id            int       `json:"id,omitempty"`
			CurrentEditor user      `json:"current_editor,omitempty"`
			Data          string    `json:"data,omitempty"`
			Time          time.Time `json:"time,omitempty"`
			NoteType      int       `json:"note_type,omitempty"`
		} `json:"history,omitempty"`
		Entry    string    `json:"entry,omitempty"`
		Date     time.Time `json:"date,omitempty"`
		Private  bool      `json:"private,omitempty"`
		Edited   bool      `json:"edited,omitempty"`
		EditTime time.Time `json:"edit_time,omitempty"`
		NoteType int       `json:"note_type,omitempty"`
	} `json:"notes,omitempty"`
	Files []struct {
		Id    int    `json:"id,omitempty"`
		File  string `json:"file,omitempty"`
		Title string `json:"title,omitempty"`
	} `json:"files,omitempty"`
	RiskAcceptance []int `json:"risk_acceptance,omitempty"`
}

type user struct {
	Id        int    `json:"id,omitempty"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

type product struct {
	Id            int      `json:"id,omitempty"`
	FindingsCount int      `json:"findings_count,omitempty"`
	FindingsList  []int    `json:"findings_list,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	ProductMeta   []struct {
		Name  string `json:"name,omitempty"`
		Value string `json:"value,omitempty"`
	} `json:"product_meta,omitempty"`
	Name                       string     `json:"name,omitempty"`
	Description                string     `json:"description,omitempty"`
	Created                    *time.Time `json:"created,omitempty"`
	ProdNumericGrade           int        `json:"prod_numeric_grade,omitempty"`
	BusinessCriticality        string     `json:"business_criticality,omitempty"`
	Platform                   string     `json:"platform,omitempty"`
	Lifecycle                  string     `json:"lifecycle,omitempty"`
	Origin                     string     `json:"origin,omitempty"`
	UserRecords                int        `json:"user_records,omitempty"`
	Revenue                    string     `json:"revenue,omitempty"`
	ExternalAudience           bool       `json:"external_audience,omitempty"`
	InternetAccessible         bool       `json:"internet_accessible,omitempty"`
	EnableSimpleRiskAcceptance bool       `json:"enable_simple_risk_acceptance,omitempty"`
	EnableFullRiskAcceptance   bool       `json:"enable_full_risk_acceptance,omitempty"`
	ProductManager             int        `json:"product_manager,omitempty"`
	TechnicalContact           int        `json:"technical_contact,omitempty"`
	TeamManager                int        `json:"team_manager,omitempty"`
	ProdType                   int        `json:"prod_type,omitempty"`
	SlaConfiguration           int        `json:"sla_configuration,omitempty"`
	Members                    []int      `json:"members,omitempty"`
	AuthorizationGroups        []int      `json:"authorization_groups,omitempty"`
	Regulations                []int      `json:"regulations,omitempty"`
}

type productType struct {
	Id              int       `json:"id,omitempty"`
	Name            string    `json:"name,omitempty"`
	Description     string    `json:"description,omitempty"`
	CriticalProduct bool      `json:"critical_product,omitempty"`
	KeyProduct      bool      `json:"key_product,omitempty"`
	Updated         time.Time `json:"updated,omitempty"`
	Created         time.Time `json:"created,omitempty"`
	Members         []int     `json:"members,omitempty"`
}

type scanImportResponse struct {
	ScanDate                  string     `json:"scan_date"`
	MinimumSeverity           string     `json:"minimum_severity"`
	Active                    bool       `json:"active"`
	Verified                  bool       `json:"verified"`
	ScanType                  string     `json:"scan_type"`
	EndpointToAdd             int        `json:"endpoint_to_add"`
	File                      string     `json:"file"`
	ProductTypeName           string     `json:"product_type_name"`
	ProductName               string     `json:"product_name"`
	EngagementName            string     `json:"engagement_name"`
	Engagement                int        `json:"engagement"`
	TestTitle                 string     `json:"test_title"`
	AutoCreateContext         bool       `json:"auto_create_context"`
	DeduplicationOnEngagement bool       `json:"deduplication_on_engagement"`
	Lead                      int        `json:"lead"`
	Tags                      []string   `json:"tags"`
	CloseOldFindings          bool       `json:"close_old_findings"`
	PushToJira                bool       `json:"push_to_jira"`
	Environment               string     `json:"environment"`
	Version                   string     `json:"version"`
	BuildId                   string     `json:"build_id"`
	BranchTag                 string     `json:"branch_tag"`
	CommitHash                string     `json:"commit_hash"`
	ApiScanConfiguration      int        `json:"api_scan_configuration"`
	Service                   string     `json:"service"`
	GroupBy                   string     `json:"group_by"`
	Test                      int        `json:"test"`
	TestId                    int        `json:"test_id"`
	EngagementId              int        `json:"engagement_id"`
	ProductId                 int        `json:"product_id"`
	ProductTypeId             int        `json:"product_type_id"`
	Statistics                statistics `json:"statistics"`
}

type statistics struct {
	Before vulnerabilityGroup `json:"before"`
	Delta  vulnerabilityGroup `json:"delta"`
	After  vulnerabilityGroup `json:"after"`
}

type vulnerabilityGroup struct {
	Info     vulnerability `json:"info"`
	Low      vulnerability `json:"low"`
	Medium   vulnerability `json:"medium"`
	High     vulnerability `json:"high"`
	Critical vulnerability `json:"critical"`
	Total    vulnerability `json:"total"`
}

type vulnerability struct {
	Active       int `json:"active"`
	Verified     int `json:"verified"`
	Duplicate    int `json:"duplicate"`
	FalseP       int `json:"false_p"`
	OutOfScope   int `json:"out_of_scope"`
	IsMitigated  int `json:"is_mitigated"`
	RiskAccepted int `json:"risk_accepted"`
	Total        int `json:"total"`
}

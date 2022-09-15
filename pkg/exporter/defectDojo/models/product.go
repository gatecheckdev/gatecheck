package models

import "time"

type Product struct {
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

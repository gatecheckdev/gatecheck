package artifact

import (
	"errors"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gatecheckdev/gatecheck/internal/log"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type CyclonedxSbomReport cdx.BOM

var ErrCyclonedxValidationFailed = errors.New("cyclonedx validation failed")

var severityOrder = gcStrings.StrOrder{"Critical", "High", "Medium", "Low", "Info", "None", "Unknown"}

func (r CyclonedxSbomReport) String() string {
	log.Infof("Parsing and Displaying Cyclone SBOM")

	// Build Components Table
	bomStr := ""
	if (&r).Components != nil {
		bomStr = r.bomString()
	}

	// Build Vulnerabilities Table
	vulnsStr := ""
	if (&r).Vulnerabilities != nil {
		vulnsStr = r.vulnsString()
	}

	return fmt.Sprintf("%s\n%s", bomStr, vulnsStr)
}

func (r CyclonedxSbomReport) bomString() string {
	bomTable := new(gcStrings.Table).WithHeader("Name", "Version", "Type", "Ref")
	for _, item := range *r.Components {
		bomTable = bomTable.WithRow(
			item.Name,
			item.Version,
			string(item.Type),
			gcStrings.CleanAndAbbreviate(item.BOMRef, 50))
	}

	// Sort the rows by Type then Name
	bomTable = bomTable.SortBy([]gcStrings.SortBy{
		{Name: "Type", Mode: gcStrings.Asc},
		{Name: "Name", Mode: gcStrings.Asc},
	}).Sort()

	totals := gcStrings.PrettyPrintMap(bomTable.TotalsByCol(2))
	bomTable = bomTable.WithFooter(fmt.Sprintf(" Total: %d %s", bomTable.NumRows(), totals))

	return bomTable.String()
}

func (r CyclonedxSbomReport) vulnsString() string {
	vulnTable := new(gcStrings.Table).WithHeader("Severity", "Package", "Version", "Exploitability", "Link")
	for _, item := range *r.Vulnerabilities {
		severity := findSeverity(item)
		analysis := getAnalysis(item)
		// log.Infof("Advisories: %d", len(item.Advisories))
		advisory := getFirstAdvisoryURL(item.Advisories)

		if (&item).Affects == nil {
			vulnTable = vulnTable.WithRow(severity, (&item).ID, "Not Specified", analysis, advisory)
			continue
		}
		for _, a := range *item.Affects {
			comp := findComponentInSBOM(a.Ref, r)
			vulnTable = vulnTable.WithRow(severity, comp.Name, comp.Version, analysis, advisory)
		}
	}

	// Sort the rows by Severity then Package
	vulnTable = vulnTable.SortBy([]gcStrings.SortBy{
		{Name: "Severity", Mode: gcStrings.AscCustom, Order: severityOrder},
		{Name: "Package", Mode: gcStrings.Asc},
	}).Sort()

	totals := gcStrings.PrettyPrintMap(vulnTable.TotalsByCol(0))
	vulnTable = vulnTable.WithFooter(fmt.Sprintf(" Total: %d %s", vulnTable.NumRows(), totals))

	return vulnTable.String()
}

// Adds the components that are not vulnerabilities as one with severity as none
func (r *CyclonedxSbomReport) ShimComponentsAsVulnerabilities() *CyclonedxSbomReport {
	nv := cdx.Vulnerability{
		ID: "",
		Ratings: &[]cdx.VulnerabilityRating{
			{
				Severity: cdx.SeverityNone,
			},
		},
		Description:    " ",
		Recommendation: " ",
		Analysis: &cdx.VulnerabilityAnalysis{
			State:  cdx.IASNotAffected,
			Detail: "Gatecheck added to be reported as a component of the product.",
		},
		Affects: &[]cdx.Affects{},
	}
	for _, c := range *r.Components {
		*nv.Affects = append(*nv.Affects, cdx.Affects{Ref: c.BOMRef})
	}
	if r.Vulnerabilities == nil {
		r.Vulnerabilities = &[]cdx.Vulnerability{}
	}
	*r.Vulnerabilities = append(*r.Vulnerabilities, nv)
	return r
}

type CyclonedxConfig struct {
	AllowList []CyclonedxListItem `yaml:"allowList,omitempty" json:"allowList,omitempty"`
	DenyList  []CyclonedxListItem `yaml:"denyList,omitempty" json:"denyList,omitempty"`
	Critical  int                 `yaml:"critical"   json:"critical"`
	High      int                 `yaml:"high"       json:"high"`
	Medium    int                 `yaml:"medium"     json:"medium"`
	Low       int                 `yaml:"low"        json:"low"`
	Info      int                 `yaml:"info"       json:"info"`
	None      int                 `yaml:"none"       json:"none"`
	Unknown   int                 `yaml:"unknown"    json:"unknown"`
}

type CyclonedxListItem struct {
	Id     string `yaml:"id"     json:"id"`
	Reason string `yaml:"reason" json:"reason"`
}

func ValidateCyclonedx(config CyclonedxConfig, scanReport CyclonedxSbomReport) error {
	found := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0, "None": 0, "Unknown": 0}
	allowed := map[string]int{
		"Critical": config.Critical, "High": config.High, "Medium": config.Medium,
		"Low": config.Low, "None": config.None, "Info": config.Info, "Unknown": config.Unknown,
	}
	foundDenied := make([]cdx.Vulnerability, 0)

LOOPMATCH:
	for _, item := range *scanReport.Vulnerabilities {

		for _, allowed := range config.AllowList {
			if strings.Compare((&item).ID, allowed.Id) == 0 {

				log.Infof("%s Allowed. Reason: %s", (&item).ID, allowed.Reason)
				continue LOOPMATCH
			}
		}

		for _, denied := range config.DenyList {
			if (&item).ID == denied.Id {
				log.Infof("%s Denied. Reason: %s", (&item).ID, denied.Reason)
				foundDenied = append(foundDenied, item)
			}
		}

		found[findSeverity(item)] += 1
	}
	log.Infof("CycloneDx Findings: %v", gcStrings.PrettyPrintMap(found))

	var errStrings []string

	for severity := range found {
		// A -1 in config means all allowed
		if allowed[severity] == -1 {
			continue
		}
		if found[severity] > allowed[severity] {
			s := fmt.Sprintf("%s (%d found > %d allowed)", severity, found[severity], allowed[severity])
			errStrings = append(errStrings, s)
		}
	}

	if len(foundDenied) != 0 {
		deniedReport := &CyclonedxSbomReport{Vulnerabilities: &foundDenied}
		errStrings = append(errStrings, fmt.Sprintf("Denied Vulnerabilities\n%s", deniedReport))
	}

	if len(errStrings) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrCyclonedxValidationFailed, strings.Join(errStrings, ", "))
}

// Iterate through the sbom looking for a component that matches the reference
func findComponentInSBOM(ref string, sbom CyclonedxSbomReport) cdx.Component {
	// If the component is not found, use the ref as default
	comp := cdx.Component{
		Name: gcStrings.CleanAndAbbreviate(ref, 50),
	}
	if (&sbom).Components == nil {
		return comp
	}
	for _, c := range *sbom.Components {
		if c.BOMRef == ref {
			return c
		}
	}
	return comp
}

// Iterate through all ratings and return the specific severity from the source or the highest severity
//
//	See Trivy's explanation of which source to use:
//		https://aquasecurity.github.io/trivy/latest/docs/vulnerability/detection/data-source/#data-source-selection
func findSeverity(v cdx.Vulnerability) string {
	// Grab lowest severity
	severity := severityOrder[len(severityOrder)-1]

	for _, rating := range *v.Ratings {
		c := cases.Title(language.English)
		s := c.String(string(rating.Severity))
		// If the vuln source matches the rating source, use that severity
		if (&v).Source != nil && rating.Source != nil {
			if v.Source.Name == rating.Source.Name {
				return s
			}
		}

		if severityOrder.Index(s) < severityOrder.Index(severity) {
			severity = s
		}
	}
	return severity
}

// Get the VEX/analysis to determine the exploitability
func getAnalysis(v cdx.Vulnerability) string {
	if (&v).Analysis != nil {
		return fmt.Sprintf("%s/%s", v.Analysis.State, v.Analysis.Justification)
	}
	return ""
}

func getFirstAdvisoryURL(advisories *[]cdx.Advisory) string {
	if advisories != nil && len(*advisories) > 0 {
		return (*advisories)[0].URL
	}
	return "None Specified"
}

package artifact

import (
	"bytes"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"gopkg.in/yaml.v3"
)

func TestConfig(t *testing.T) {
	config := &GrypeConfig{
		AllowList: []GrypeListItem{{
			Id:     "cve123",
			Reason: "some reason",
		}},
		DenyList: []GrypeListItem{{
			Id:     "cve123",
			Reason: "some deny reason",
		}},
	}

	buf := new(bytes.Buffer)

	yaml.NewEncoder(buf).Encode(config)

	t.Logf("\n%s", buf)
}

func TestAllowList(t *testing.T) {
	report := &GrypeScanReport{}
	addVul(report, "Critical", "CVE-2023-1")
	addVul(report, "High", "CVE-2023-2")
	addVul(report, "Medium", "CVE-2023-3")

	config := NewConfig()
	config.Grype.Critical = 0
	config.Grype.AllowList = []GrypeListItem{{Id: "CVE-2023-1", Reason: "Because..."}}

	t.Log(config.Grype.AllowList)

	t.Log(report)

	if err := ValidateGrype(*config.Grype, *report); err != nil {
		t.Fatal(err)
	}
}

func TestDenyList(t *testing.T) {
	report := &GrypeScanReport{}
	addVul(report, "Critical", "CVE-2023-1")
	addVul(report, "High", "CVE-2023-2")
	addVul(report, "Low", "CVE-2023-3")

	config := NewConfig()
	config.Grype.Critical = 0
	config.Grype.DenyList = []GrypeListItem{{Id: "CVE-2023-3", Reason: "Because..."}}

	t.Log(config.Grype.DenyList)

	t.Log(report)

	if err := ValidateGrype(*config.Grype, *report); err == nil {
		t.Fatal("Expected Validation error for CVE-2023-3")
	}
}

func addVul(r *GrypeScanReport, severity string, id string) {
	vul := models.Vulnerability{
		VulnerabilityMetadata: models.VulnerabilityMetadata{Severity: severity, ID: id, DataSource: "mock.link"},
		Fix:                   models.Fix{},
		Advisories:            []models.Advisory{},
	}
	match := models.Match{Vulnerability: vul, Artifact: models.Package{Name: "mock package name", Version: "v1.x.x"}}
	r.Matches = append(r.Matches, match)
}

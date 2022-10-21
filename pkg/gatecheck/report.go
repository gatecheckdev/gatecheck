package gatecheck

import (
	"errors"
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/semgrep"
	"strings"
	"time"
)

var ErrorValidation = errors.New("report failed validation")

type Settings struct {
	ProjectName string
	PipelineId  string
	PipelineUrl string
}

type Report struct {
	ProjectName string `json:"projectName"`
	PipelineId  string `json:"pipelineId"`
	PipelineUrl string `json:"pipelineUrl"`
	Timestamp   string `json:"timestamp"`
	Artifacts   struct {
		Grype    *grype.Artifact    `json:"grype,omitempty"`
		Semgrep  *semgrep.Artifact  `json:"semgrep,omitempty"`
		Gitleaks *gitleaks.Artifact `json:"gitleaks,omitempty"`
	} `json:"artifacts"`
}

func NewReport(projectName string) *Report {
	return &Report{
		ProjectName: projectName,
		PipelineId:  "pipeline-id",
		PipelineUrl: "pipeline-url",
		Timestamp:   time.Now().String(),
	}
}

// WithConfig will configure each Artifact if the config is defined
func (r Report) WithConfig(c *Config) *Report {
	if c == nil {
		return &r
	}
	r.ProjectName = c.ProjectName

	if c.Grype != nil {
		if r.Artifacts.Grype == nil {
			r.Artifacts.Grype = grype.NewArtifact()
		}
		r.Artifacts.Grype = r.Artifacts.Grype.WithConfig(c.Grype)
	}

	if c.Semgrep != nil {
		if r.Artifacts.Semgrep == nil {
			r.Artifacts.Semgrep = semgrep.NewArtifact()
		}
		r.Artifacts.Semgrep = r.Artifacts.Semgrep.WithConfig(c.Semgrep)
	}

	if c.Gitleaks != nil {
		if r.Artifacts.Gitleaks == nil {
			r.Artifacts.Gitleaks = gitleaks.NewArtifact()
		}
		r.Artifacts.Gitleaks = r.Artifacts.Gitleaks.WithConfig(c.Gitleaks)
	}

	return &r
}

func (r Report) WithSettings(s Settings) *Report {
	if s.ProjectName != "" {
		r.ProjectName = s.ProjectName
	}
	if s.PipelineId != "" {
		r.PipelineId = s.PipelineId
	}
	if s.PipelineUrl != "" {
		r.PipelineUrl = s.PipelineUrl
	}
	return &r
}

// Validate calls the validate function for each artifact
func (r Report) Validate() error {
	var allErrors []error
	var errorDescriptions []string
	for _, artifact := range r.artifacts() {

		if err := artifact.Validate(); err != nil {
			allErrors = append(allErrors, err)
			errorDescriptions = append(errorDescriptions, err.Error())
		}
	}
	if len(allErrors) != 0 {
		return fmt.Errorf("%w : %s", ErrorValidation,
			strings.Join(errorDescriptions, "\n"))
	}

	return nil
}

func (r Report) artifacts() []Artifact {
	var activeArtifacts []Artifact
	if r.Artifacts.Grype != nil {
		activeArtifacts = append(activeArtifacts, r.Artifacts.Grype)
	}
	if r.Artifacts.Semgrep != nil {
		activeArtifacts = append(activeArtifacts, r.Artifacts.Semgrep)
	}
	if r.Artifacts.Gitleaks != nil {
		activeArtifacts = append(activeArtifacts, r.Artifacts.Gitleaks)
	}
	return activeArtifacts
}

func (r Report) String() string {
	var out strings.Builder
	divider := strings.Repeat("-", 25) + "\n"
	out.WriteString(r.ProjectName + " " + r.PipelineId + "\n")
	out.WriteString(r.PipelineUrl + "\n")

	for _, artifact := range r.artifacts() {
		if artifact != nil {
			out.WriteString(divider)
			out.WriteString(artifact.String())
		}
	}

	return out.String()
}

type Artifact interface {
	Validate() error
	fmt.Stringer
}

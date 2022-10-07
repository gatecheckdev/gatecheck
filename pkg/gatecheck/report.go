package gatecheck

import (
	"errors"
	"fmt"
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
		Grype   grype.Artifact   `json:"grype,omitempty"`
		Semgrep semgrep.Artifact `json:"semgrep,omitempty"`
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

func (r Report) WithConfig(c *Config) *Report {
	r.ProjectName = c.ProjectName
	r.Artifacts.Grype = *r.Artifacts.Grype.WithConfig(&c.Grype)
	r.Artifacts.Semgrep = *r.Artifacts.Semgrep.WithConfig(&c.Semgrep)
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
	return []Artifact{
		r.Artifacts.Grype,
		r.Artifacts.Semgrep,
	}
}

func (r Report) String() string {
	var out strings.Builder
	divider := strings.Repeat("-", 25) + "\n"
	out.WriteString(r.ProjectName + " " + r.PipelineId + "\n")
	out.WriteString(r.PipelineUrl + "\n")
	out.WriteString(divider)
	out.WriteString(r.Artifacts.Grype.String())
	out.WriteString(divider)
	out.WriteString(r.Artifacts.Semgrep.String())
	return out.String()
}

type Artifact interface {
	Validate() error
	fmt.Stringer
}

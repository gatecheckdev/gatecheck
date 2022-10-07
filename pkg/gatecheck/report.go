package gatecheck

import (
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"strings"
	"time"
)

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
		Grype grype.Artifact `json:"grype"`
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

func (r Report) String() string {
	var out strings.Builder
	divider := strings.Repeat("-", 25) + "\n"
	out.WriteString(r.ProjectName + " " + r.PipelineId + "\n")
	out.WriteString(r.PipelineUrl + "\n")
	out.WriteString(divider)
	out.WriteString(r.Artifacts.Grype.String())
	return out.String()
}

package report

import (
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"io"
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

func (r Report) WithConfig(c *config.Config) *Report {
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

type Writer struct {
	writer io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{writer: w}
}

func (w *Writer) Write(p []byte) (int, error) {
	return w.writer.Write(p)
}

func (w *Writer) WriteReport(r *Report) error {

	return json.NewEncoder(w).Encode(r)
}

type Reader struct {
	reader io.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{reader: r}
}

func (r *Reader) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *Reader) ReadReport() (*Report, error) {
	report := &Report{}
	err := json.NewDecoder(r).Decode(report)
	return report, err
}

package report

import (
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"io"
	"time"
)

type basicReport struct {
	ProjectName string `json:"projectName"`
	PipelineId  string `json:"pipelineId"`
	PipelineUrl string `json:"pipelineUrl"`
	Timestamp   string `json:"timestamp"`
	Artifacts   struct {
		Grype grype.Artifact `json:"grype"`
	} `json:"artifacts"`
}

func NewReport(projectName string) *basicReport {
	return &basicReport{
		ProjectName: projectName,
		PipelineId:  "pipeline-id",
		PipelineUrl: "pipeline-url",
		Timestamp:   time.Now().String(),
	}
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

func (w *Writer) WriteReport(r *basicReport) error {

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

func (r *Reader) ReadReport() (*basicReport, error) {
	report := &basicReport{}
	err := json.NewDecoder(r).Decode(report)
	return report, err
}

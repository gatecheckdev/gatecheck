package config

import (
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"gopkg.in/yaml.v2"
	"io"
)

type basicConfig struct {
	ProjectName string       `yaml:"ProjectName"`
	Grype       grype.Config `yaml:"grype"`
}

func NewConfig(projectName string) *basicConfig {
	return &basicConfig{
		ProjectName: projectName,
		Grype:       *grype.NewConfig(-1),
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

func (w *Writer) WriteConfig(c *basicConfig) error {
	return yaml.NewEncoder(w).Encode(c)
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

func (r *Reader) ReadConfig() (*basicConfig, error) {
	config := &basicConfig{}
	err := yaml.NewDecoder(r).Decode(config)
	return config, err
}

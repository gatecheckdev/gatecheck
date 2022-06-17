package grype

import (
	"gopkg.in/yaml.v2"
	"io"
)

type Config struct {
	Critical   int `yaml:"critical"`
	High       int `yaml:"high"`
	Medium     int `yaml:"medium"`
	Low        int `yaml:"low"`
	Negligible int `yaml:"negligible"`
	Unknown    int `yaml:"unknown"`
}

func NewConfig(v int) *Config {
	return &Config{
		Critical:   v,
		High:       v,
		Medium:     v,
		Low:        v,
		Negligible: v,
		Unknown:    v,
	}
}

type ConfigWriter struct {
	writer io.Writer
}

func (w ConfigWriter) Write(p []byte) (n int, err error) {
	return w.writer.Write(p)
}

func NewConfigWriter(w io.Writer) *ConfigWriter {
	return &ConfigWriter{writer: w}
}

// WriteConfig to the underlying writer. See NewConfigWriter
func (w *ConfigWriter) WriteConfig(config *Config) error {
	return yaml.NewEncoder(w).Encode(&config)
}

type ConfigReader struct {
	reader io.Reader
}

func (r *ConfigReader) Read(p []byte) (n int, err error) {
	return r.reader.Read(p)
}

// ReadConfig from the underlying reader. See NewConfigReader
func (r *ConfigReader) ReadConfig() (Config, error) {
	config := Config{}
	err := yaml.NewDecoder(r.reader).Decode(&config)
	return config, err
}

func NewConfigReader(r io.Reader) *ConfigReader {
	return &ConfigReader{reader: r}
}

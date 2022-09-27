package config

import (
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
)

type Config struct {
	ProjectName string       `yaml:"ProjectName"`
	Grype       grype.Config `yaml:"grype"`
}

func NewConfig(projectName string) *Config {
	return &Config{
		ProjectName: projectName,
		Grype:       *grype.NewConfig(-1),
	}
}

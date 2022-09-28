package config

import (
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
)

type Config struct {
	ProjectName string       `yaml:"ProjectName" json:"projectName"`
	Grype       grype.Config `yaml:"grype" json:"grype"`
}

func NewConfig(projectName string) *Config {
	return &Config{
		ProjectName: projectName,
		Grype:       *grype.NewConfig(-1),
	}
}

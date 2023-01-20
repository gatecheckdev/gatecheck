package artifact

type Config struct {
	Grype    *GrypeConfig    `yaml:"grype,omitempty" json:"grype,omitempty"`
	Semgrep  *SemgrepConfig  `yaml:"semgrep,omitempty" json:"semgrep,omitempty"`
	Gitleaks *GitleaksConfig `yaml:"gitleaks,omitempty" json:"gitleaks,omitempty"`
}

func NewConfig() *Config {
	return &Config{
		Grype:    &GrypeConfig{Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1},
		Semgrep:  &SemgrepConfig{Info: -1, Warning: -1, Error: -1},
		Gitleaks: &GitleaksConfig{SecretsAllowed: false},
	}
}

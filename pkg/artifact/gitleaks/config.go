package gitleaks

type Config struct {
	SecretsAllowed bool `json:"secretsAllowed"`
}

func NewConfig(b bool) *Config {
	return &Config{SecretsAllowed: b}
}

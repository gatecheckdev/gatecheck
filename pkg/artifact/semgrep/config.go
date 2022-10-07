package semgrep

type Config struct {
	Info    int `yaml:"info" json:"info"`
	Warning int `yaml:"warning" json:"warning"`
	Error   int `yaml:"error" json:"error"`
}

func NewConfig(v int) *Config {
	return &Config{
		Info:    v,
		Warning: v,
		Error:   v,
	}
}

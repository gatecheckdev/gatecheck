package grype

type Config struct {
	Critical   int `yaml:"critical" json:"critical"`
	High       int `yaml:"high" json:"high"`
	Medium     int `yaml:"medium" json:"medium"`
	Low        int `yaml:"low" json:"low"`
	Negligible int `yaml:"negligible" json:"negligible"`
	Unknown    int `yaml:"unknown" json:"unknown"`
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

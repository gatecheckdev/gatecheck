package grype

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

package config

import (
	"os"
	"gopkg.in/yaml.v3"
)

type Config struct {
	App struct {
		Name    string `yaml:"name"`
		Version string `yaml:"version"`
	} `yaml:"app"`
	Cache struct {
		Enabled   bool   `yaml:"enabled"`
		TTL       int    `yaml:"ttl"`
		Directory string `yaml:"directory"`
	} `yaml:"cache"`
	Concurrency struct {
		Workers int `yaml:"workers"`
		Timeout int `yaml:"timeout"`
		Retries int `yaml:"retries"`
	} `yaml:"concurrency"`
	Logging struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"logging"`
	Theme struct {
		Mode string `yaml:"mode"`
	} `yaml:"theme"`
	APIKeys struct {
		VirusTotal     string `yaml:"virustotal"`
		Shodan         string `yaml:"shodan"`
		Censys         string `yaml:"censys"`
		SecurityTrails string `yaml:"securitytrails"`
		AbuseIPDB      string `yaml:"abuseipdb"`
		Ipinfo         string `yaml:"ipinfo"`
		URLScan        string `yaml:"urlscan"`
		GreyNoise      string `yaml:"greynoise"`
	} `yaml:"api_keys"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

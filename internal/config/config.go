package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type TLSConfig struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type Config struct {
	Listen          string     `json:"listen"`
	TLS             *TLSConfig `json:"tls,omitempty"`
	UpstreamBaseURL string     `json:"upstream_base_url,omitempty"`
}

type Upstream struct {
	OAuthToken string `json:"oauthToken"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8788"
	}
	if c.UpstreamBaseURL == "" {
		c.UpstreamBaseURL = "https://api.anthropic.com"
	}
	return &c, nil
}

func LoadUpstream(path string) (*Upstream, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read upstream: %w", err)
	}
	var u Upstream
	if err := json.Unmarshal(b, &u); err != nil {
		return nil, fmt.Errorf("parse upstream: %w", err)
	}
	if u.OAuthToken == "" {
		return nil, fmt.Errorf("upstream.json: oauthToken is empty")
	}
	return &u, nil
}

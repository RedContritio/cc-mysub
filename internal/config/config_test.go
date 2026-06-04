package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"listen":"127.0.0.1:9000"}`), 0o600)

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9000" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.UpstreamBaseURL != "https://api.anthropic.com" {
		t.Errorf("UpstreamBaseURL default = %q", cfg.UpstreamBaseURL)
	}
}

func TestLoadUpstream(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "upstream.json")
	os.WriteFile(p, []byte(`{"oauthToken":"sk-ant-oat01-XYZ"}`), 0o600)

	up, err := LoadUpstream(p)
	if err != nil {
		t.Fatalf("LoadUpstream: %v", err)
	}
	if up.OAuthToken != "sk-ant-oat01-XYZ" {
		t.Errorf("OAuthToken = %q", up.OAuthToken)
	}
}

func TestLoadUpstreamRejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "upstream.json")
	os.WriteFile(p, []byte(`{"oauthToken":""}`), 0o600)
	if _, err := LoadUpstream(p); err == nil {
		t.Fatal("expected error on empty oauthToken")
	}
}

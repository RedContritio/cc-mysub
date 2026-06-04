package main

import (
	"testing"

	"github.com/redcontritio/cc-mysub/internal/config"
)

func TestServeChoosesTLSAndFailsOnMissingCert(t *testing.T) {
	cfg := &config.Config{
		Listen: "127.0.0.1:0",
		TLS:    &config.TLSConfig{Cert: "/nonexistent", Key: "/nonexistent"},
	}
	if err := serve(cfg, nil); err == nil {
		t.Error("expected error from missing cert in TLS branch")
	}
}

package main

import (
	"net/http"

	"github.com/redcontritio/cc-mysub/internal/config"
)

// serve starts an HTTP or HTTPS server depending on cfg.TLS. When cfg.TLS has
// both cert and key, it listens with TLS (self-signed or ACME); otherwise plain
// HTTP (channel encryption is then the entry layer's job — see ARCHITECTURE.md).
func serve(cfg *config.Config, h http.Handler) error {
	srv := &http.Server{Addr: cfg.Listen, Handler: h}
	if cfg.TLS != nil && cfg.TLS.Cert != "" && cfg.TLS.Key != "" {
		return srv.ListenAndServeTLS(cfg.TLS.Cert, cfg.TLS.Key)
	}
	return srv.ListenAndServe()
}

package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/config"
	"github.com/redcontritio/cc-mysub/internal/proxy"
)

func main() {
	cfgDir := flag.String("config-dir", defaultConfigDir(), "config directory")
	flag.Parse()

	cfg, err := config.LoadConfig(filepath.Join(*cfgDir, "config.json"))
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	up, err := config.LoadUpstream(filepath.Join(*cfgDir, "upstream.json"))
	if err != nil {
		slog.Error("load upstream", "err", err)
		os.Exit(1)
	}
	store, err := auth.NewDeviceStore(filepath.Join(*cfgDir, "devices.json"))
	if err != nil {
		slog.Error("load devices", "err", err)
		os.Exit(1)
	}
	store.StartWatch()

	p, err := proxy.New(cfg.UpstreamBaseURL, up.OAuthToken)
	if err != nil {
		slog.Error("build proxy", "err", err)
		os.Exit(1)
	}

	// Chain: Auth → RateLimit → AccessLog → proxy.
	// AccessLog runs innermost so it sees the auth-injected device and the
	// real upstream status; 401/429 are emitted by their own middleware.
	handler := proxy.AuthMiddleware(store)(
		proxy.RateLimitByDevice(120)(
			proxy.AccessLog(nil)(p.Handler()),
		),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.Handle("/", handler)

	slog.Info("cc-mysub starting", "addr", cfg.Listen, "upstream", cfg.UpstreamBaseURL)
	if err := serve(cfg, mux); err != nil {
		slog.Error("server exited", "err", err)
		os.Exit(1)
	}
}

func defaultConfigDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "cc-mysub")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "cc-mysub")
}

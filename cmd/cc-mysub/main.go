package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/config"
	"github.com/redcontritio/cc-mysub/internal/enroll"
	"github.com/redcontritio/cc-mysub/internal/mitm"
	"github.com/redcontritio/cc-mysub/internal/proxy"
)

func main() {
	// Subcommands. Bare invocation (no subcommand) still serves, so launchd and
	// existing `cc-mysub [--config-dir ...]` usage keep working unchanged.
	if len(os.Args) > 1 && os.Args[1] == "add-device" {
		if err := enroll.Run(os.Args[2:], defaultConfigDir(), os.Stdout); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return
			}
			fmt.Fprintln(os.Stderr, "add-device:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "helper" {
		os.Exit(runHelper(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "device-init" {
		os.Exit(runDeviceInit(os.Args[2:], defaultConfigDir(), os.Stdout))
	}
	if len(os.Args) > 1 && os.Args[1] == "gen-config" {
		os.Exit(runGenConfig(os.Args[2:], defaultConfigDir(), os.Stdout))
	}

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

	// 加载 cc-mysub CA：既作外层 TLS 身份的现签根，也作内层 MITM 现签根。
	caCert, err := os.ReadFile(filepath.Join(*cfgDir, "ca.crt"))
	if err != nil {
		slog.Error("read ca.crt", "err", err)
		os.Exit(1)
	}
	caKey, err := os.ReadFile(filepath.Join(*cfgDir, "ca.key"))
	if err != nil {
		slog.Error("read ca.key", "err", err)
		os.Exit(1)
	}
	ca, err := mitm.LoadCA(caCert, caKey)
	if err != nil {
		slog.Error("load ca", "err", err)
		os.Exit(1)
	}
	minter := mitm.NewMinter(ca, time.Hour)

	// 外层 TLS 身份 = 真 LE 证书，从 <config-dir>/certs/<public_host>.{crt,key} 加载（续期热重载）。
	// 缺 public_host 无从定位证书路径，fail-fast。
	if cfg.Client == nil || cfg.Client.PublicHost == "" {
		slog.Error("client.public_host required (outer-TLS identity cert path)")
		os.Exit(1)
	}
	outerCertPath := filepath.Join(*cfgDir, "certs", cfg.Client.PublicHost+".crt")
	outerKeyPath := filepath.Join(*cfgDir, "certs", cfg.Client.PublicHost+".key")
	outerCert := proxy.NewOuterCertLoader(outerCertPath, outerKeyPath)
	if _, err := outerCert(nil); err != nil {
		slog.Error("load outer TLS cert", "cert", outerCertPath, "err", err)
		os.Exit(1)
	}

	// forward-proxy serving chain：conditionalAuth → RateLimit → AccessLog → forwardSwap（见 NewForwardProxy）。
	// CONNECT 目标分类由 internal/hosts.Classify 权威裁决（MITM 换 token / 透传盲隧道 / 403）——
	// 与设备 splitter 共用同一事实源。fail-closed：自家域名后缀通配收口，第三方精确登记。
	fp := proxy.NewForwardProxy(minter, store, up, nil, outerCert, 512)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		slog.Error("listen", "addr", cfg.Listen, "err", err)
		os.Exit(1)
	}
	slog.Info("cc-mysub forward-proxy starting", "addr", cfg.Listen, "identity", cfg.Client.PublicHost)
	if err := fp.Serve(ln); err != nil {
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

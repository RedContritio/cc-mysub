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
		if err := enroll.Run(os.Args[2:], os.Stdout); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return
			}
			fmt.Fprintln(os.Stderr, "add-device:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "remove-device" {
		if err := enroll.RunRemove(os.Args[2:], os.Stdout); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return
			}
			fmt.Fprintln(os.Stderr, "remove-device:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "helper" {
		os.Exit(runHelper(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "device-init" {
		os.Exit(runDeviceInit(os.Args[2:], os.Stdout))
	}
	if len(os.Args) > 1 && os.Args[1] == "gen-config" {
		os.Exit(runGenConfig(os.Args[2:], os.Stdout, os.Stderr))
	}

	cfgDir := flag.String("config-dir", "", "config directory (默认: $XDG_CONFIG_HOME/cc-mysub 或 ~/.config/cc-mysub)")
	flag.Parse()
	if *cfgDir == "" {
		*cfgDir = defaultConfigDir()
	}

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

	// 加载 cc-mysub 自有 CA：仅作内层 MITM 现签根（api/console.anthropic.com 叶证书）。
	// 外层 TLS 身份用真 LE 证书（见下文 certs/<public_host>.{crt,key}），不靠此 CA。
	caCert, err := os.ReadFile(filepath.Join(*cfgDir, "ca.crt"))
	if err != nil {
		slog.Error("read ca.crt", "err", err)
		os.Exit(1)
	}
	caKeyPath := filepath.Join(*cfgDir, "ca.key")
	if err := config.RequireOwnerOnly(caKeyPath); err != nil {
		slog.Error("ca.key permission", "err", err)
		os.Exit(1)
	}
	caKey, err := os.ReadFile(caKeyPath)
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
	// 启动探载即走 loader 的完整校验(含私钥权限位,且此后每次握手复检——Backlog P2),
	// 单独的启动期 RequireOwnerOnly 是死防御,已删。
	if _, err := outerCert(nil); err != nil {
		slog.Error("load outer TLS cert", "cert", outerCertPath, "err", err)
		os.Exit(1)
	}

	// forward-proxy serving chain：conditionalAuth → RateLimit → AccessLog → forwardSwap（见 NewForwardProxy）。
	// CONNECT 目标分类由 internal/hosts.Classify 权威裁决（MITM 换 token / 透传盲隧道 / 403）——
	// 与设备 splitter 共用同一事实源。fail-closed：自家域名后缀通配收口，第三方精确登记。
	fp := proxy.NewForwardProxy(minter, store, up, nil, outerCert, 512)
	// 设备从 devices.json 删除(吊销)时,主动断开其既有外层连接,使吊销即时生效(P1-2)。
	// 在 StartWatch 前设回调,确保第一次热重载就能触发主动断开。
	store.SetOnRevoke(fp.RevokeConns)
	store.StartWatch()

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

// defaultConfigDir 返回默认配置目录，解析失败即 fail-fast（slog.Error + os.Exit(1)）——
// 仅服务主路径在 --config-dir 缺省时调用；显式 --config-dir 不经过这里（Backlog P1：
// launchd 最小环境无 HOME + plist 钉死 --config-dir 时必须可启动）。子命令自行调
// config.DefaultDir 并把错误作 error 返回。
func defaultConfigDir() string {
	dir, err := config.DefaultDir()
	if err != nil {
		slog.Error("default config dir", "err", err)
		os.Exit(1)
	}
	return dir
}

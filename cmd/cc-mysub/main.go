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
	if len(os.Args) > 1 && os.Args[1] == "remove-device" {
		if err := enroll.RunRemove(os.Args[2:], defaultConfigDir(), os.Stdout); err != nil {
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
		os.Exit(runDeviceInit(os.Args[2:], defaultConfigDir(), os.Stdout))
	}
	if len(os.Args) > 1 && os.Args[1] == "gen-config" {
		os.Exit(runGenConfig(os.Args[2:], defaultConfigDir(), os.Stdout, os.Stderr))
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
	if err := config.RequireOwnerOnly(outerKeyPath); err != nil {
		slog.Error("outer TLS key permission", "err", err)
		os.Exit(1)
	}
	outerCert := proxy.NewOuterCertLoader(outerCertPath, outerKeyPath)
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

// resolveConfigDir 解析默认配置目录：优先 XDG_CONFIG_HOME，否则用户主目录下 .config/cc-mysub。
// HOME/用户主目录不可解析时返回 error——绝不静默回退到文件系统根下的 /.config/cc-mysub。
// LaunchDaemon 的最小环境不含 HOME，os.UserHomeDir 此时返回错误；若把错误丢给 `_` 并继续，
// 配置目录会静默解析为根路径、读不到 operator 写入的真实配置，进而 LoadConfig 失败 + KeepAlive
// 无限 crash-loop（错误只落在 /tmp 日志）。错误可见纪律要求此处 fail-fast 而非静默回退。
func resolveConfigDir() (string, error) {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "cc-mysub"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("无法确定配置目录: %w; 请设置 XDG_CONFIG_HOME 或显式传 --config-dir", err)
	}
	return filepath.Join(home, ".config", "cc-mysub"), nil
}

// defaultConfigDir 返回默认配置目录，解析失败即 fail-fast（slog.Error + os.Exit(1)）——
// 所有子命令与服务主路径共用此默认值，不静默用根路径继续。
func defaultConfigDir() string {
	dir, err := resolveConfigDir()
	if err != nil {
		slog.Error("default config dir", "err", err)
		os.Exit(1)
	}
	return dir
}

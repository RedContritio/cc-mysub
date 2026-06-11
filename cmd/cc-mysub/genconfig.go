package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/redcontritio/cc-mysub/internal/config"
)

// DeployConfig 是 operator 经 gen-config 产出、发布给设备的部署配置。全部为面向部署的
// 公开常量（public_host 域名、ca_cert_pem 是内层 MITM CA 公证书、release 坐标）；无密钥。
type DeployConfig struct {
	PublicHost       string `json:"public_host"`
	SubscriptionType string `json:"subscription_type"`
	ReleaseRepo      string `json:"release_repo"`
	ReleaseTag       string `json:"release_tag"`
	CACertPEM        string `json:"ca_cert_pem"`
}

// runGenConfig 读 <cfgDir>/config.json 的 client 段 + <cfgDir>/ca.crt，产出部署配置 JSON 到 out。
// -config-dir 缺省时惰性解析 config.DefaultDir()（显式目录绝不触发 XDG/HOME 解析，Backlog P1），
// 与 add-device 的 -config-dir 一致，使 e2e/测试可指向任意目录。
//
// 仅部署 JSON 写 out（正常路径=stdout，供 `gen-config ... > deploy.json` 重定向）；所有诊断/错误/
// usage 写 errOut（正常路径=stderr）。否则按 README 重定向后任一错误文本会落进 deploy.json、终端无
// 信号，operator 未查退出码即把含错误文本的产物当部署配置发布（错误可见纪律）。
func runGenConfig(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("gen-config", flag.ContinueOnError)
	fs.SetOutput(errOut)
	configDir := fs.String("config-dir", "", "config directory (默认: $XDG_CONFIG_HOME/cc-mysub 或 ~/.config/cc-mysub)")
	release := fs.String("release", "", "cc-mysub release tag (必填, 如 v1.0.0)")
	repo := fs.String("release-repo", "", "release 托管 owner/repo (覆盖 config client.release_repo)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfgDir := *configDir
	if cfgDir == "" {
		d, err := config.DefaultDir()
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		cfgDir = d
	}
	cfg, err := config.LoadConfig(filepath.Join(cfgDir, "config.json"))
	if err != nil {
		fmt.Fprintln(errOut, "load config:", err)
		return 1
	}
	if cfg.Client == nil || cfg.Client.PublicHost == "" {
		fmt.Fprintln(errOut, "config client.public_host required")
		return 1
	}
	if *release == "" {
		fmt.Fprintln(errOut, "--release required (e.g. --release v1.0.0)")
		return 1
	}
	// subscription_type 与 public_host/--release 对称 fail-fast：缺失即报错要求显式填写真实档位，
	// 绝不静默默认成档位最高的 max（与 SECURITY.md「请按你实际持有的档位填写」一致，也守「禁止静默
	// 返回默认值」纪律——pro/team 订阅者漏配会让全部设备被自我声明为 max）。
	if cfg.Client.SubscriptionType == "" {
		fmt.Fprintln(errOut, "config client.subscription_type required (按你实际持有的档位填写: pro/max/team/enterprise)")
		return 1
	}
	repoVal := *repo
	if repoVal == "" {
		repoVal = cfg.Client.ReleaseRepo
	}
	if repoVal == "" {
		repoVal = "redcontritio/cc-mysub"
	}
	caPEM, err := os.ReadFile(filepath.Join(cfgDir, "ca.crt"))
	if err != nil {
		fmt.Fprintln(errOut, "read ca.crt (先跑 add-device 生成 CA):", err)
		return 1
	}
	dc := DeployConfig{
		PublicHost:       cfg.Client.PublicHost,
		SubscriptionType: cfg.Client.SubscriptionType,
		ReleaseRepo:      repoVal,
		ReleaseTag:       *release,
		CACertPEM:        string(caPEM),
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(dc); err != nil {
		fmt.Fprintln(errOut, "encode:", err)
		return 1
	}
	return 0
}

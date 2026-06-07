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
// cfgDir 为默认配置目录（main 分发 defaultConfigDir()）；-config-dir flag 可覆盖之，
// 与 add-device 的 -config-dir 一致，使 e2e/测试可指向任意目录。
func runGenConfig(args []string, cfgDir string, out io.Writer) int {
	fs := flag.NewFlagSet("gen-config", flag.ContinueOnError)
	fs.SetOutput(out)
	configDir := fs.String("config-dir", cfgDir, "config directory (默认 = 默认配置目录)")
	release := fs.String("release", "", "cc-mysub release tag (必填, 如 v1.0.0)")
	repo := fs.String("release-repo", "", "release 托管 owner/repo (覆盖 config client.release_repo)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfgDir = *configDir
	cfg, err := config.LoadConfig(filepath.Join(cfgDir, "config.json"))
	if err != nil {
		fmt.Fprintln(out, "load config:", err)
		return 1
	}
	if cfg.Client == nil || cfg.Client.PublicHost == "" {
		fmt.Fprintln(out, "config client.public_host required")
		return 1
	}
	if *release == "" {
		fmt.Fprintln(out, "--release required (e.g. --release v1.0.0)")
		return 1
	}
	repoVal := *repo
	if repoVal == "" {
		repoVal = cfg.Client.ReleaseRepo
	}
	if repoVal == "" {
		repoVal = "redcontritio/cc-mysub"
	}
	subType := cfg.Client.SubscriptionType
	if subType == "" {
		subType = "max"
	}
	caPEM, err := os.ReadFile(filepath.Join(cfgDir, "ca.crt"))
	if err != nil {
		fmt.Fprintln(out, "read ca.crt (先跑 add-device 生成 CA):", err)
		return 1
	}
	dc := DeployConfig{
		PublicHost:       cfg.Client.PublicHost,
		SubscriptionType: subType,
		ReleaseRepo:      repoVal,
		ReleaseTag:       *release,
		CACertPEM:        string(caPEM),
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(dc); err != nil {
		fmt.Fprintln(out, "encode:", err)
		return 1
	}
	return 0
}

// Package enroll signs a per-device token and emits a ready-to-run `myclaude`
// wrapper for that device. It is the `cc-mysub add-device` subcommand's engine.
//
// The deployment-facing constants (proxy host, frps IP, subscription tier) are
// fixed per deployment and read once from config.json's `client` section; only
// the device label and token vary per device. Flags override config per call.
package enroll

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/config"
)

//go:embed myclaude.tmpl
var wrapperTmpl string

// deviceCACertPath 是 wrapper 在目标设备上引用 cc-mysub CA 公证书的固定路径。
// add-device 生成 ca.crt 于服务端 config-dir，操作者将其拷到设备的此路径；
// wrapper 的 --ca / NODE_EXTRA_CA_CERTS 都指向它。用 ${HOME} 由设备运行时展开。
const deviceCACertPath = "${HOME}/.config/cc-mysub/ca.crt"

// Params are the resolved values needed to enroll one device.
type Params struct {
	Label       string
	PublicHost  string
	SubType     string
	RateLimit   int
	Upstream    string // 该设备所属 setup-token id; 空 = 使用默认 token
	ReleaseRepo string // 托管 release 二进制的 GitHub owner/repo override; 空走 config/默认
}

// resolveFingerprint 从 --fingerprint（小写归一后校验）或 --client-cert（读 DER 算指纹）得出
// 设备证书指纹。二者择一必填——这是"逐设备认证"的操作者准入动作。
func resolveFingerprint(fingerprint, clientCertPath string) (string, error) {
	if fingerprint != "" {
		fp := strings.ToLower(strings.TrimSpace(fingerprint))
		if !auth.CanonicalFingerprint(fp) {
			return "", fmt.Errorf("--fingerprint %q 非法 (须 64 位 hex)", fingerprint)
		}
		return fp, nil
	}
	if clientCertPath != "" {
		b, err := os.ReadFile(clientCertPath)
		if err != nil {
			return "", fmt.Errorf("read --client-cert: %w", err)
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return "", fmt.Errorf("--client-cert %q 无 PEM 证书块", clientCertPath)
		}
		return auth.CertFingerprint(blk.Bytes), nil
	}
	return "", fmt.Errorf("需要 --fingerprint <hex> 或 --client-cert <file> (由设备 device-init 产出)")
}

// RenderWrapper 渲染 v4 自举型 myclaude wrapper。除 p+token 的 per-device 值外，它内联
// cc-mysub CA 公证书（caCertPEM，使设备无需另拷 ca.crt），并烤入 per-platform 二进制 sha256
// 表（shaTable，恰四个受支持平台——其完整性由 ParseManifest 在网络边界保证）+ release 下载根
// releaseBase，使 wrapper 首次运行能自取并校验 cc-mysub 二进制。caCertPath 是设备侧 wrapper
// 写出内联 CA 的路径；version 烤为运维注释。
func RenderWrapper(p Params, caCertPath, caCertPEM string, shaTable map[string]string, version, releaseBase string) (string, error) {
	t, err := template.New("myclaude").Parse(wrapperTmpl)
	if err != nil {
		return "", fmt.Errorf("parse wrapper template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, struct {
		PublicHost, SubType, CACertPath string
		CACertPEM, Version, ReleaseBase string
		ShaLinuxAmd64, ShaLinuxArm64    string
		ShaDarwinAmd64, ShaDarwinArm64  string
	}{
		p.PublicHost, p.SubType, caCertPath,
		caCertPEM, version, releaseBase,
		shaTable["linux-amd64"], shaTable["linux-arm64"],
		shaTable["darwin-amd64"], shaTable["darwin-arm64"],
	}); err != nil {
		return "", fmt.Errorf("render wrapper: %w", err)
	}
	return buf.String(), nil
}

// Resolve merges config-provided client defaults with per-call flag overrides
// and validates required fields. A non-empty override field wins over config.
func Resolve(def *config.ClientConfig, override Params) (Params, error) {
	out := override
	if def != nil {
		if out.PublicHost == "" {
			out.PublicHost = def.PublicHost
		}
		if out.SubType == "" {
			out.SubType = def.SubscriptionType
		}
		if out.ReleaseRepo == "" {
			out.ReleaseRepo = def.ReleaseRepo
		}
	}
	if out.ReleaseRepo == "" {
		out.ReleaseRepo = "redcontritio/cc-mysub" // release 二进制托管点默认仓库
	}
	if out.Label == "" {
		return Params{}, fmt.Errorf("--label is required")
	}
	if out.PublicHost == "" {
		return Params{}, fmt.Errorf("public host is required (config client.public_host or --host)")
	}
	if out.SubType == "" {
		return Params{}, fmt.Errorf("subscription type is required (config client.subscription_type or --sub)")
	}
	return out, nil
}

// AppendDevice appends a device to the JSON array at path (creating it if the
// file is absent or empty), storing only the sha256 of token. It rejects a
// duplicate label so an enrollment never silently shadows an existing device.
func AppendDevice(path string, p Params, certSHA256 string) error {
	var list []auth.Device
	if b, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, &list); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}

	for _, d := range list {
		if d.Label == p.Label {
			return fmt.Errorf("device label %q already exists in %s", p.Label, path)
		}
	}

	list = append(list, auth.Device{
		Label:      p.Label,
		CertSHA256: certSHA256,
		RateLimit:  p.RateLimit,
		Upstream:   p.Upstream,
	})

	out, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("encode devices: %w", err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// ReplaceDevice 原子替换 path 中 label==p.Label 的设备行：删旧行（吊销旧 token）+ 追加新行
// （新 token），单次 WriteFile。label 不存在时报错（rotate 无可替换者——新设备用不带 --rotate
// 的 add-device）。这是 --rotate 路径，使「换 token」真正原地发生，不旁留旧凭据为有效。
func ReplaceDevice(path string, p Params, certSHA256 string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var list []auth.Device
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	out := make([]auth.Device, 0, len(list))
	found := false
	for _, d := range list {
		if d.Label == p.Label {
			found = true
			continue // 丢弃旧行 = 吊销旧 token
		}
		out = append(out, d)
	}
	if !found {
		return fmt.Errorf("device label %q not found in %s (nothing to rotate)", p.Label, path)
	}
	out = append(out, auth.Device{
		Label:      p.Label,
		CertSHA256: certSHA256,
		RateLimit:  p.RateLimit,
		Upstream:   p.Upstream,
	})
	enc, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encode devices: %w", err)
	}
	enc = append(enc, '\n')
	if err := os.WriteFile(path, enc, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// releaseTagRE / releaseRepoRE 约束 --release tag 与 release_repo 的字符集。两者都被逐字
// 插入生成的 wrapper（RELEASE_BASE 双引号 bash 字面量 + 版本注释），含 shell 元字符的值会
// 产出损坏/可注入的 wrapper。add-device 期 raise 使诚实 typo 立即可见（错误可见），而非静默
// 产出坏 wrapper；owner-trusted 下这是契约校验，非反恶意防御。
var (
	releaseTagRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
	releaseRepoRE = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
)

// Run is the `cc-mysub add-device` entrypoint: it parses args, loads the client
// defaults from <config-dir>/config.json, resolves params, signs a token,
// appends it to <config-dir>/devices.json, writes the filled wrapper, and prints
// next steps. defaultCfgDir is the fallback when --config-dir is not given.
func Run(args []string, defaultCfgDir string, out io.Writer) error {
	fs := flag.NewFlagSet("add-device", flag.ContinueOnError)
	fs.SetOutput(out)
	var (
		cfgDir      = fs.String("config-dir", defaultCfgDir, "config directory")
		label       = fs.String("label", "", "device label (required, unique)")
		host        = fs.String("host", "", "proxy public host (overrides config client.public_host)")
		sub         = fs.String("sub", "", "subscription tier: pro/max/team/enterprise (overrides config)")
		rate        = fs.Int("rate-limit", 0, "per-minute request cap for this device (0 = proxy default)")
		upstream    = fs.String("upstream", "", "setup-token id this device draws from (empty = default token)")
		outPath     = fs.String("out", "", "wrapper output path (default ./myclaude-<label>)")
		release     = fs.String("release", "", "cc-mysub 二进制 release tag, 如 v1.0.0 (必填, 无默认 latest)")
		relRepo     = fs.String("release-repo", "", "托管 release 二进制的 GitHub owner/repo (覆盖 config client.release_repo)")
		rotate      = fs.Bool("rotate", false, "对已存在的 label 原地换发: 删旧指纹 + 写新指纹 + 覆写 wrapper")
		fingerprint = fs.String("fingerprint", "", "设备证书 SHA-256(DER) 指纹 (device-init 打印; 必填, 或 --client-cert)")
		clientCert  = fs.String("client-cert", "", "设备证书文件 (自动算指纹; --fingerprint 的替代)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadConfig(filepath.Join(*cfgDir, "config.json"))
	if err != nil {
		return err
	}

	p, err := Resolve(cfg.Client, Params{
		Label:       *label,
		PublicHost:  *host,
		SubType:     *sub,
		RateLimit:   *rate,
		Upstream:    *upstream,
		ReleaseRepo: *relRepo,
	})
	if err != nil {
		return err
	}

	if *release == "" {
		return fmt.Errorf("--release is required (e.g. --release v1.0.0)")
	}
	if !releaseTagRE.MatchString(*release) {
		return fmt.Errorf("--release %q has invalid chars (allowed: letters digits . _ / -)", *release)
	}
	if !releaseRepoRE.MatchString(p.ReleaseRepo) {
		return fmt.Errorf("release repo %q must be owner/repo (letters digits . _ -)", p.ReleaseRepo)
	}

	// 先拉 manifest（网络, 可失败）——置于任何落盘副作用之前, 失败时不遗留 orphan 设备行。
	shaTable, err := fetchManifest(nil, p.ReleaseRepo, *release)
	if err != nil {
		return err
	}

	// 一次性建立 cc-mysub 自有 CA（幂等：ca.crt 已存在则复用，绝不重生成）。
	// serverCACertPath 是服务端 config-dir 下的 ca.crt，需拷到设备的 deviceCACertPath。
	serverCACertPath, err := EnsureCA(*cfgDir, "cc-mysub CA")
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(serverCACertPath)
	if err != nil {
		return fmt.Errorf("read CA cert %s: %w", serverCACertPath, err)
	}

	fp, err := resolveFingerprint(*fingerprint, *clientCert)
	if err != nil {
		return err
	}

	devicesPath := filepath.Join(*cfgDir, "devices.json")
	if *rotate {
		if err := ReplaceDevice(devicesPath, p, fp); err != nil {
			return err
		}
	} else {
		if err := AppendDevice(devicesPath, p, fp); err != nil {
			return err
		}
	}

	releaseBase := releaseDownloadBase(p.ReleaseRepo, *release)
	// wrapper 引用设备侧固定路径（运行时由设备 ${HOME} 展开），并内联 CA + sha 表 + release 根。
	wrapper, err := RenderWrapper(p, deviceCACertPath, string(caPEM), shaTable, *release, releaseBase)
	if err != nil {
		return err
	}

	dest := *outPath
	if dest == "" {
		dest = "myclaude-" + p.Label
	}
	if err := os.WriteFile(dest, []byte(wrapper), 0o700); err != nil {
		return fmt.Errorf("write wrapper %s: %w", dest, err)
	}
	absDest, _ := filepath.Abs(dest)

	fmt.Fprintf(out, "✓ 已登记设备 %q (证书指纹 %s) 到 %s\n", p.Label, fp, devicesPath)
	fmt.Fprintf(out, "\n通用 wrapper 已生成(无 per-device 秘密, 全 fleet 复用同一文件) —— 拷到设备 PATH (如 ~/.local/bin/myclaude):\n  %s\n", absDest)
	fmt.Fprintf(out, "  设备首次运行自动: 按 uname 下载 cc-mysub 二进制(sha256 校验 fail-closed) + 写出内联 CA + device-init 本地生成密钥/证书并打印指纹(私钥不离设备)。\n")
	fmt.Fprintf(out, "  (本设备指纹已在上面登记; 新设备 = 设备跑一次得指纹 → add-device --fingerprint 登记 → re-run。)\n")
	fmt.Fprintf(out, "\n代理热重载会自动加载新设备, 无需重启。吊销 = 删 %s 里该条; 换证书 = 设备重 device-init + add-device --rotate --label %s --fingerprint <newfp>。\n", devicesPath, p.Label)
	return nil
}

// 以下三个常量与函数构成 release 资产寻址层。base URL 经 env override 是给「真二进制
// out-of-process e2e」的注入缝（in-process 单测亦可经同一 env 注入 httptest URL）。

const releaseBaseEnv = "CC_MYSUB_RELEASE_BASE_URL"
const defaultReleaseBase = "https://github.com"

// releaseBaseURL 返回 release 下载根，优先 env override（去尾斜杠），否则 GitHub。
func releaseBaseURL() string {
	if v := os.Getenv(releaseBaseEnv); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultReleaseBase
}

// releaseDownloadBase 构造某 tag 的资产下载根：<base>/<repo>/releases/download/<tag>（无尾斜杠）。
func releaseDownloadBase(repo, tag string) string {
	return fmt.Sprintf("%s/%s/releases/download/%s", releaseBaseURL(), repo, tag)
}

// fetchManifest 下载并解析 repo@tag 的 SHA256SUMS。先显式查 StatusCode：非 200 即报清晰的
// 「release tag 未找到」错误，避免 typo'd tag 的 404 HTML 被 ParseManifest 误报成「缺平台」
// （治理总纲：错误可见 + 概念精度）。client 为 nil 时用带超时的默认 client。
func fetchManifest(client *http.Client, repo, tag string) (map[string]string, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	url := releaseDownloadBase(repo, tag) + "/SHA256SUMS"
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch SHA256SUMS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release tag %q not found or SHA256SUMS asset missing (HTTP %d)", tag, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read SHA256SUMS: %w", err)
	}
	return ParseManifest(string(b))
}

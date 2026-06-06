// Package enroll signs a per-device token and emits a ready-to-run `myclaude`
// wrapper for that device. It is the `cc-mysub add-device` subcommand's engine.
//
// The deployment-facing constants (proxy host, frps IP, subscription tier) are
// fixed per deployment and read once from config.json's `client` section; only
// the device label and token vary per device. Flags override config per call.
package enroll

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/template"

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
	FrpsIP      string
	ProxyPort   int
	SubType     string
	RateLimit   int
	Upstream    string // 该设备所属 setup-token id; 空 = 使用默认 token
	ReleaseRepo string // 托管 release 二进制的 GitHub owner/repo override; 空走 config/默认
}

// GenerateToken returns a fresh per-device token: "cco_dev_" + 48 hex chars
// (24 random bytes). It carries none of the real setup-token; it is a door-card
// number whose sha256 the proxy checks against devices.json.
func GenerateToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return "cco_dev_" + hex.EncodeToString(b[:]), nil
}

// RenderWrapper renders the v4 myclaude wrapper for p + token. caCertPath is the
// device-side path to the cc-mysub CA cert (where the operator places ca.crt);
// the wrapper references it for both --ca and NODE_EXTRA_CA_CERTS. The wrapper
// never bakes in a small model — that choice is left to the user (commented
// example).
func RenderWrapper(p Params, token, caCertPath string) (string, error) {
	t, err := template.New("myclaude").Parse(wrapperTmpl)
	if err != nil {
		return "", fmt.Errorf("parse wrapper template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, struct {
		PublicHost, FrpsIP               string
		ProxyPort                        int
		DeviceToken, SubType, CACertPath string
	}{p.PublicHost, p.FrpsIP, p.ProxyPort, token, p.SubType, caCertPath}); err != nil {
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
		if out.FrpsIP == "" {
			out.FrpsIP = def.FrpsIP
		}
		if out.ProxyPort == 0 {
			out.ProxyPort = def.ProxyPort
		}
		if out.SubType == "" {
			out.SubType = def.SubscriptionType
		}
		if out.ReleaseRepo == "" {
			out.ReleaseRepo = def.ReleaseRepo
		}
	}
	if out.ProxyPort == 0 {
		out.ProxyPort = 8788 // frp 暴露的 cc-mysub forward-proxy 默认端口
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
	if out.FrpsIP == "" {
		return Params{}, fmt.Errorf("frps IP is required (config client.frps_ip or --frps-ip)")
	}
	if out.SubType == "" {
		return Params{}, fmt.Errorf("subscription type is required (config client.subscription_type or --sub)")
	}
	return out, nil
}

// AppendDevice appends a device to the JSON array at path (creating it if the
// file is absent or empty), storing only the sha256 of token. It rejects a
// duplicate label so an enrollment never silently shadows an existing device.
func AppendDevice(path string, p Params, token string) error {
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
		Label:       p.Label,
		TokenSHA256: auth.HashToken(token),
		RateLimit:   p.RateLimit,
		Upstream:    p.Upstream,
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

// Run is the `cc-mysub add-device` entrypoint: it parses args, loads the client
// defaults from <config-dir>/config.json, resolves params, signs a token,
// appends it to <config-dir>/devices.json, writes the filled wrapper, and prints
// next steps. defaultCfgDir is the fallback when --config-dir is not given.
func Run(args []string, defaultCfgDir string, out io.Writer) error {
	fs := flag.NewFlagSet("add-device", flag.ContinueOnError)
	fs.SetOutput(out)
	var (
		cfgDir   = fs.String("config-dir", defaultCfgDir, "config directory")
		label    = fs.String("label", "", "device label (required, unique)")
		host     = fs.String("host", "", "proxy public host (overrides config client.public_host)")
		frpsIP   = fs.String("frps-ip", "", "frps public IP (overrides config client.frps_ip)")
		sub      = fs.String("sub", "", "subscription tier: pro/max/team/enterprise (overrides config)")
		rate     = fs.Int("rate-limit", 0, "per-minute request cap for this device (0 = proxy default)")
		upstream = fs.String("upstream", "", "setup-token id this device draws from (empty = default token)")
		outPath  = fs.String("out", "", "wrapper output path (default ./myclaude-<label>)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadConfig(filepath.Join(*cfgDir, "config.json"))
	if err != nil {
		return err
	}

	p, err := Resolve(cfg.Client, Params{
		Label:      *label,
		PublicHost: *host,
		FrpsIP:     *frpsIP,
		SubType:    *sub,
		RateLimit:  *rate,
		Upstream:   *upstream,
	})
	if err != nil {
		return err
	}

	// 一次性建立 cc-mysub 自有 CA（幂等：ca.crt 已存在则复用，绝不重生成）。
	// serverCACertPath 是服务端 config-dir 下的 ca.crt，需拷到设备的 deviceCACertPath。
	serverCACertPath, err := EnsureCA(*cfgDir, "cc-mysub CA")
	if err != nil {
		return err
	}

	token, err := GenerateToken()
	if err != nil {
		return err
	}

	devicesPath := filepath.Join(*cfgDir, "devices.json")
	if err := AppendDevice(devicesPath, p, token); err != nil {
		return err
	}

	// wrapper 引用设备侧固定路径（运行时由设备 ${HOME} 展开），不是服务端路径。
	wrapper, err := RenderWrapper(p, token, deviceCACertPath)
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
	absCA, _ := filepath.Abs(serverCACertPath)

	fmt.Fprintf(out, "✓ 已为设备 %q 签发 per-device token 并写入 %s\n", p.Label, devicesPath)
	fmt.Fprintf(out, "\nper-device token (交给该设备, 明文仅此一次):\n  %s\n", token)
	fmt.Fprintf(out, "\ncc-mysub CA 公证书 (拷到该设备的 %s):\n  %s\n", deviceCACertPath, absCA)
	fmt.Fprintf(out, "\nwrapper 已生成 (拷到该设备的 PATH, 如 ~/.local/bin/myclaude):\n  %s\n", absDest)
	fmt.Fprintf(out, "\n代理热重载会自动加载新设备, 无需重启。吊销 = 删 %s 里该条。\n", devicesPath)
	return nil
}

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

// Params are the resolved values needed to enroll one device.
type Params struct {
	Label      string
	PublicHost string
	FrpsIP     string
	SubType    string
	RateLimit  int
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

// RenderWrapper renders the myclaude wrapper for p + token. The wrapper never
// bakes in a small model — that choice is left to the user (commented example).
func RenderWrapper(p Params, token string) (string, error) {
	t, err := template.New("myclaude").Parse(wrapperTmpl)
	if err != nil {
		return "", fmt.Errorf("parse wrapper template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, struct {
		PublicHost, FrpsIP, DeviceToken, SubType string
	}{p.PublicHost, p.FrpsIP, token, p.SubType}); err != nil {
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
		if out.SubType == "" {
			out.SubType = def.SubscriptionType
		}
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
		cfgDir  = fs.String("config-dir", defaultCfgDir, "config directory")
		label   = fs.String("label", "", "device label (required, unique)")
		host    = fs.String("host", "", "proxy public host (overrides config client.public_host)")
		frpsIP  = fs.String("frps-ip", "", "frps public IP (overrides config client.frps_ip)")
		sub     = fs.String("sub", "", "subscription tier: pro/max/team/enterprise (overrides config)")
		rate    = fs.Int("rate-limit", 0, "per-minute request cap for this device (0 = proxy default)")
		outPath = fs.String("out", "", "wrapper output path (default ./myclaude-<label>)")
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
	})
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

	wrapper, err := RenderWrapper(p, token)
	if err != nil {
		return err
	}

	dest := *outPath
	if dest == "" {
		dest = "myclaude-" + p.Label
	}
	if err := os.WriteFile(dest, []byte(wrapper), 0o755); err != nil {
		return fmt.Errorf("write wrapper %s: %w", dest, err)
	}
	absDest, _ := filepath.Abs(dest)

	fmt.Fprintf(out, "✓ 已为设备 %q 签发 per-device token 并写入 %s\n", p.Label, devicesPath)
	fmt.Fprintf(out, "\nper-device token (交给该设备, 明文仅此一次):\n  %s\n", token)
	fmt.Fprintf(out, "\nwrapper 已生成 (拷到该设备的 PATH, 如 ~/.local/bin/myclaude):\n  %s\n", absDest)
	fmt.Fprintf(out, "\n代理热重载会自动加载新设备, 无需重启。吊销 = 删 %s 里该条。\n", devicesPath)
	return nil
}

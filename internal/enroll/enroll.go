// Package enroll registers a per-device certificate fingerprint into the
// proxy's device store and establishes the cc-mysub CA. It is the engine of the
// `cc-mysub add-device` subcommand (the operator's device-approval action).
//
// Device-side concerns—downloading the binary, writing the CA, generating the
// per-device key/cert, and emitting the `myclaude` wrapper—are owned entirely by
// install.sh; add-device no longer renders or distributes a wrapper. The
// deployment-facing constants (proxy host, subscription tier) are fixed per
// deployment and read once from config.json's `client` section; only the device
// label and fingerprint vary per device. Flags override config per call.
package enroll

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/config"
)

// Params are the resolved values needed to enroll one device.
type Params struct {
	Label      string
	PublicHost string
	SubType    string
	RateLimit  int
	Upstream   string // 该设备所属 setup-token id; 空 = 使用默认 token
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

// Resolve merges config-provided client defaults with per-call flag overrides
// and validates required fields. A non-empty override field wins over config.
//
// SubType is still resolved (config default / --sub override) so callers may pin
// it, but it is no longer required: add-device only registers a fingerprint now,
// the subscription tier is deployment metadata carried to devices via gen-config,
// not by add-device. PublicHost stays required (it is the deployment identity).
func Resolve(def *config.ClientConfig, override Params) (Params, error) {
	out := override
	if def != nil {
		if out.PublicHost == "" {
			out.PublicHost = def.PublicHost
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

	return writeDevices(path, list)
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
	return writeDevices(path, out)
}

// writeDevices 原子写设备列表:MarshalIndent → 临时文件 → rename(同目录 rename 原子)。所有改动
// devices.json 的 cli 路径(append/replace/remove)共用,使 store.reload 的 mtime polling 永远读到
// 完整合法 JSON——配合「吊销也走 cli」,P2-4 的 half-write / 手动写坏导致的解析失败场景根本不出现。
func writeDevices(path string, list []auth.Device) error {
	enc, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("encode devices: %w", err)
	}
	enc = append(enc, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".devices-*.tmp")
	if err != nil {
		return fmt.Errorf("temp %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功后为 no-op
	if _, err := tmp.Write(enc); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}

// RemoveDevice 删除 path 中匹配的设备(指纹优先,否则 label)并原子写回——吊销走 cli 而非手动编辑
// devices.json。无匹配报错(错误可见,不静默成功)。
func RemoveDevice(path, fingerprint, label string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var list []auth.Device
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	out := make([]auth.Device, 0, len(list))
	removed := 0
	for _, d := range list {
		if (fingerprint != "" && d.CertSHA256 == fingerprint) || (fingerprint == "" && d.Label == label) {
			removed++
			continue
		}
		out = append(out, d)
	}
	if removed == 0 {
		return fmt.Errorf("no device matched in %s (fingerprint=%q label=%q)", path, fingerprint, label)
	}
	return writeDevices(path, out)
}

// Run is the `cc-mysub add-device` entrypoint: it parses args, loads the client
// defaults from <config-dir>/config.json, resolves params, ensures the cc-mysub
// CA exists, registers (or rotates) the device's certificate fingerprint into
// <config-dir>/devices.json, and prints next steps. It emits no wrapper—device
// onboarding is owned by install.sh. defaultCfgDir is the fallback when
// --config-dir is not given.
func Run(args []string, defaultCfgDir string, out io.Writer) error {
	fs := flag.NewFlagSet("add-device", flag.ContinueOnError)
	fs.SetOutput(out)
	var (
		cfgDir      = fs.String("config-dir", defaultCfgDir, "config directory")
		label       = fs.String("label", "", "device label (required, unique)")
		host        = fs.String("host", "", "proxy public host (overrides config client.public_host)")
		sub         = fs.String("sub", "", "subscription tier (overrides config; 仅用于校验 Resolve 一致性)")
		rate        = fs.Int("rate-limit", 0, "per-minute request cap for this device (0 = proxy default)")
		upstream    = fs.String("upstream", "", "setup-token id this device draws from (empty = default token)")
		rotate      = fs.Bool("rotate", false, "对已存在的 label 原地换发: 删旧指纹 + 写新指纹")
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
		Label:      *label,
		PublicHost: *host,
		SubType:    *sub,
		RateLimit:  *rate,
		Upstream:   *upstream,
	})
	if err != nil {
		return err
	}
	// 首次建立 cc-mysub CA（幂等）；ca.crt 经 gen-config 内联进部署配置下发设备。
	if _, err := EnsureCA(*cfgDir, "cc-mysub CA"); err != nil {
		return err
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
	fmt.Fprintf(out, "✓ 已登记设备 %q (证书指纹 %s) 到 %s\n", p.Label, fp, devicesPath)
	fmt.Fprintf(out, "设备侧用 install.sh 自助入网(见 README); 该指纹经 add-device 已授权, 设备轮询将自动通过。\n")
	fmt.Fprintf(out, "吊销=cc-mysub remove-device --label %s (或 --fingerprint <fp>); 换证书=设备重 device-init + add-device --rotate --label %s --fingerprint <newfp>。\n", p.Label, p.Label)
	return nil
}

// RunRemove is the `cc-mysub remove-device` entrypoint: 按 --fingerprint 或 --label 从
// <config-dir>/devices.json 删除设备并原子写回(吊销走 cli,不手动编辑)。热重载后该设备立即失效。
func RunRemove(args []string, defaultCfgDir string, out io.Writer) error {
	fs := flag.NewFlagSet("remove-device", flag.ContinueOnError)
	fs.SetOutput(out)
	var (
		cfgDir      = fs.String("config-dir", defaultCfgDir, "config directory")
		fingerprint = fs.String("fingerprint", "", "要吊销的设备证书 SHA-256(DER) 指纹")
		label       = fs.String("label", "", "要吊销的设备 label (--fingerprint 的替代)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fingerprint == "" && *label == "" {
		return fmt.Errorf("需要 --fingerprint <hex> 或 --label <name>")
	}
	fp := ""
	if *fingerprint != "" {
		fp = strings.ToLower(strings.TrimSpace(*fingerprint))
		if !auth.CanonicalFingerprint(fp) {
			return fmt.Errorf("--fingerprint %q 非法 (须 64 位 hex)", *fingerprint)
		}
	}
	devicesPath := filepath.Join(*cfgDir, "devices.json")
	if err := RemoveDevice(devicesPath, fp, *label); err != nil {
		return err
	}
	fmt.Fprintf(out, "✓ 已吊销设备 (label=%q fingerprint=%q); 热重载后立即失效, 其他设备无感。\n", *label, fp)
	return nil
}

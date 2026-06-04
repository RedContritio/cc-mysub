package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAddDeviceSubcommand exercises the real CLI surface: it builds the binary
// and runs `cc-mysub add-device`, verifying the subcommand dispatch, flag
// parsing, the go:embed'd wrapper template, and devices.json side effect all
// work together in the compiled binary.
func TestAddDeviceSubcommand(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	bin := filepath.Join(t.TempDir(), "cc-mysub")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	cfgDir := t.TempDir()
	cfgJSON := `{"listen":"127.0.0.1:8788","client":{"public_host":"ccapi.example.com","frps_ip":"203.0.113.10","subscription_type":"max"}}`
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(cfgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(t.TempDir(), "myclaude-phone")

	out, err := exec.Command(bin, "add-device",
		"--config-dir", cfgDir, "--label", "phone", "--out", wrapper).CombinedOutput()
	if err != nil {
		t.Fatalf("add-device: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "cco_dev_") {
		t.Errorf("output missing per-device token:\n%s", out)
	}

	devices, err := os.ReadFile(filepath.Join(cfgDir, "devices.json"))
	if err != nil {
		t.Fatalf("devices.json not written: %v", err)
	}
	if !strings.Contains(string(devices), `"label": "phone"`) {
		t.Errorf("devices.json missing phone entry:\n%s", devices)
	}

	w, err := os.ReadFile(wrapper)
	if err != nil {
		t.Fatalf("wrapper not written: %v", err)
	}
	if !strings.Contains(string(w), `PROXY_HOST="ccapi.example.com"`) {
		t.Errorf("wrapper not filled from config:\n%s", w)
	}
}

// TestAddDeviceRequiresLabel verifies the contract surfaces as a non-zero exit.
func TestAddDeviceRequiresLabel(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	bin := filepath.Join(t.TempDir(), "cc-mysub")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"client":{"public_host":"h","frps_ip":"1.2.3.4","subscription_type":"max"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(bin, "add-device", "--config-dir", cfgDir).Run(); err == nil {
		t.Error("expected non-zero exit when --label is missing")
	}
}

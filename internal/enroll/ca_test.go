package enroll

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/redcontritio/cc-mysub/internal/mitm"
)

// TestEnsureCAGeneratesBoth 首次调用应生成 ca.crt(0644) 与 ca.key(0600)，
// 且产物能被 mitm.LoadCA 解析（证明是可用的 CA 对）。
func TestEnsureCAGeneratesBoth(t *testing.T) {
	dir := t.TempDir()
	certPath, err := EnsureCA(dir, "cc-mysub CA")
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if certPath != filepath.Join(dir, "ca.crt") {
		t.Errorf("certPath = %q, want %q", certPath, filepath.Join(dir, "ca.crt"))
	}

	keyPath := filepath.Join(dir, "ca.key")
	keyFI, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("ca.key not written: %v", err)
	}
	if keyFI.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode = %v, want 0600", keyFI.Mode().Perm())
	}

	certPEM := mustRead(t, certPath)
	keyPEM := mustRead(t, keyPath)
	if _, err := mitm.LoadCA(certPEM, keyPEM); err != nil {
		t.Errorf("generated CA does not load via mitm.LoadCA: %v", err)
	}
}

// TestEnsureCAIdempotent 二次调用绝不重生成：ca.crt 字节保持不变。
// 重生成会作废所有已信任旧 CA 的设备，故必须幂等。
func TestEnsureCAIdempotent(t *testing.T) {
	dir := t.TempDir()
	certPath, err := EnsureCA(dir, "cc-mysub CA")
	if err != nil {
		t.Fatalf("EnsureCA first: %v", err)
	}
	before := mustRead(t, certPath)
	keyBefore := mustRead(t, filepath.Join(dir, "ca.key"))

	certPath2, err := EnsureCA(dir, "cc-mysub CA")
	if err != nil {
		t.Fatalf("EnsureCA second: %v", err)
	}
	if certPath2 != certPath {
		t.Errorf("idempotent call returned different path %q vs %q", certPath2, certPath)
	}
	after := mustRead(t, certPath)
	keyAfter := mustRead(t, filepath.Join(dir, "ca.key"))
	if string(before) != string(after) {
		t.Error("ca.crt was regenerated on second call (must be idempotent)")
	}
	if string(keyBefore) != string(keyAfter) {
		t.Error("ca.key was regenerated on second call (must be idempotent)")
	}
}

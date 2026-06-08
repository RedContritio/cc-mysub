package enroll

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/redcontritio/cc-mysub/internal/mitm"
)

// EnsureCA 确保 cfgDir 存在 cc-mysub CA：ca.crt 已存在则原样返回其路径；否则用
// mitm.GenerateCA 生成并持久化（ca.crt 0644, ca.key 0600），返回 ca.crt 路径。
//
// 幂等是硬约束：ca.crt 已存在时绝不重生成——重生成会作废所有已信任本 CA 的设备。
func EnsureCA(cfgDir, commonName string) (caCertPath string, err error) {
	certPath := filepath.Join(cfgDir, "ca.crt")
	keyPath := filepath.Join(cfgDir, "ca.key")

	if _, err := os.Stat(certPath); err == nil {
		return certPath, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat %s: %w", certPath, err)
	}

	certPEM, keyPEM, err := mitm.GenerateCA(commonName)
	if err != nil {
		return "", fmt.Errorf("generate CA: %w", err)
	}

	// 先写私钥（0600）。私钥写失败时不应留下孤立的 ca.crt 诱导后续误判已存在。
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", keyPath, err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", certPath, err)
	}
	return certPath, nil
}

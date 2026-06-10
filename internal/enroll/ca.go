package enroll

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/redcontritio/cc-mysub/internal/mitm"
)

// EnsureCA 确保 cfgDir 存在一个可用的 cc-mysub CA 对（ca.crt + ca.key），返回 ca.crt 路径。
//
// 幂等闸不只看 ca.crt 是否存在，而是对 ca.crt 与 ca.key 同时判存并校验配对：
//   - 两者都在 → 读取并经 mitm.LoadCA 验证（可解析、IsCA、能签发）；通过则原样返回，绝不重生成
//     （重生成会作废所有已信任本 CA 的设备）；验证失败则 fail-fast 报错要求人工修复，不静默接受
//     半损坏状态拖到服务端重启或设备内层握手才以含糊错误暴露。
//   - 恰存在其一（误删/半恢复）→ 报错要求人工恢复或显式重置，绝不自动重生：否则缺 ca.crt 而
//     ca.key 在场时会截断覆盖既存私钥、不可逆地作废全部设备。
//   - 两者都不存在 → 首次生成。生成用 O_EXCL 原子创建并显式置 0600/0644，使私钥权限实际生效
//     （WriteFile 的 perm 仅在创建时生效，已有宽权限孤儿文件会保留旧权限），并堵并发首跑的覆盖。
func EnsureCA(cfgDir, commonName string) (caCertPath string, err error) {
	certPath := filepath.Join(cfgDir, "ca.crt")
	keyPath := filepath.Join(cfgDir, "ca.key")

	certExists, err := statExists(certPath)
	if err != nil {
		return "", err
	}
	keyExists, err := statExists(keyPath)
	if err != nil {
		return "", err
	}

	switch {
	case certExists && keyExists:
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", certPath, err)
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", keyPath, err)
		}
		if _, err := mitm.LoadCA(certPEM, keyPEM); err != nil {
			return "", fmt.Errorf("existing CA in %s invalid (ca.crt/ca.key 损坏或不配对): %w; 请人工修复或显式删除两者后重建, 勿留半损坏状态", cfgDir, err)
		}
		return certPath, nil
	case certExists != keyExists:
		present, missing := certPath, keyPath
		if keyExists {
			present, missing = keyPath, certPath
		}
		return "", fmt.Errorf("CA 半存在: %s 在而 %s 缺; 拒绝自动重生 (会覆盖既存私钥并作废已信任本 CA 的全部设备). 请人工恢复缺失文件, 或显式删除两者后重新建立", present, missing)
	}

	certPEM, keyPEM, err := mitm.GenerateCA(commonName)
	if err != nil {
		return "", fmt.Errorf("generate CA: %w", err)
	}
	// 先写私钥（0600）。私钥写失败时不留孤立 ca.crt 诱导后续误判已存在。
	if err := createExclusive(keyPath, keyPEM, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", keyPath, err)
	}
	if err := createExclusive(certPath, certPEM, 0o644); err != nil {
		os.Remove(keyPath) // 证书写失败:清掉孤儿私钥,避免下次落入「半存在」分支误导
		return "", fmt.Errorf("write %s: %w", certPath, err)
	}
	return certPath, nil
}

// statExists 报告 path 是否存在；NotExist 返回 false,nil,其余 stat 错误（权限/IO）原样 surface——
// 不能把它误判为「不存在」而走重生成分支覆盖既存私钥。
func statExists(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
}

// createExclusive 以 O_CREATE|O_EXCL|O_WRONLY 原子创建文件并写入：文件已存在即报错（不覆盖既存
// 内容/私钥），且 perm 经显式 mode 在创建时生效，使 0600 对抗已有宽权限孤儿文件、并堵并发首跑覆盖。
func createExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

package enroll

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// supportedPlatforms 是 wrapper 通吃的四目标（<goos>-<goarch>）。一个 wrapper 烤入全部四个
// sha256，运行时按 uname 选当前平台。
var supportedPlatforms = []string{"linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"}

// assetRE 精确匹配一个受支持的 cc-mysub release 资产 basename，捕获 (goos, goarch)。
// 任何不精确匹配此锚定模式的行——异平台（windows）、签名旁车（.minisig）、SHA256SUMS 自条目、
// 空行——一律忽略，使解析器对未来供应链签名资产前向兼容。
var assetRE = regexp.MustCompile(`^cc-mysub-(linux|darwin)-(amd64|arm64)$`)

// hexRE 校验 sha256 为小写 64-hex。
var hexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ParseManifest 把一份 release SHA256SUMS 文本解析为 platform→小写 64-hex sha256 的映射。
// 严格契约（治理总纲：意外输入必抛、禁止静默默认）：
//   - 结果须恰含全部四个受支持平台（缺任一 → error）；
//   - 匹配行 hash 非 64-hex → error；
//   - 同一平台重复 → error。
// foreign/未知资产行静默忽略（非 error），兼容 sha256sum 文本/二进制两种模式格式。
func ParseManifest(text string) (map[string]string, error) {
	out := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		// 合法 SHA256SUMS 行恰 2 字段：hash + filename。我们的资产名（cc-mysub-<os>-<arch>）
		// 绝无空白，故任一含内部空白的 filename（>2 字段）必非本资产——一律跳过，杜绝「取末 token
		// 错分类」（如 `<hash>␠␠evil cc-mysub-linux-amd64` 被误当 linux-amd64 资产、静默吸收坏 hash）。
		// 空行/短行（<2）同样跳过。缺失的真平台行由末尾 4 键完整性检查兜底报错（fail-closed）。
		if len(fields) != 2 {
			continue
		}
		hash := fields[0]
		// 二进制模式 filename 带 '*' 前缀须剥离，再取 basename 容错路径前缀。
		base := path.Base(strings.TrimPrefix(fields[1], "*"))
		m := assetRE.FindStringSubmatch(base)
		if m == nil {
			continue // foreign 资产（windows / .minisig / SHA256SUMS 自条目）
		}
		plat := m[1] + "-" + m[2]
		if !hexRE.MatchString(hash) {
			return nil, fmt.Errorf("manifest: %s 的 sha256 非 64-hex: %q", base, hash)
		}
		if _, dup := out[plat]; dup {
			return nil, fmt.Errorf("manifest: 平台 %s 重复", plat)
		}
		out[plat] = hash
	}
	for _, plat := range supportedPlatforms {
		if _, ok := out[plat]; !ok {
			return nil, fmt.Errorf("manifest: 缺平台 %s（已解析 %d/%d）", plat, len(out), len(supportedPlatforms))
		}
	}
	return out, nil
}

package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// ClientConfig holds the deployment-facing constants used to generate a
// per-device `myclaude` wrapper (see `cc-mysub add-device`). They are fixed for
// a given deployment; only the device label and token vary per device.
type ClientConfig struct {
	PublicHost       string `json:"public_host"`       // 代理对外域名 (frp https vhost); 设备拨 host:443, 外层 TLS 身份 SAN, 也是外层 LE 证书文件名
	SubscriptionType string `json:"subscription_type"` // 你的真实订阅档: pro/max/team/enterprise
	ReleaseRepo      string `json:"release_repo"`      // 托管 cc-mysub release 二进制的 GitHub owner/repo; 空=默认 redcontritio/cc-mysub
}

type Config struct {
	Listen string        `json:"listen"`
	Client *ClientConfig `json:"client,omitempty"`
}

// UpstreamToken 是 token 池中的单个条目，导出类型供跨包构造字面量（如 proxy 包测试）。
type UpstreamToken struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

type Upstream struct {
	OAuthToken  string          `json:"oauthToken,omitempty"`  // 旧单 token
	OAuthTokens []UpstreamToken `json:"oauthTokens,omitempty"` // 池
}

// PickToken 按 id 从池中取 token：id 命中返回对应 token；空 id 返回池首个（或旧单 token）；
// 未命中返回空串（调用方负责 fail）。返回空串唯一地表示「未命中」——parseUpstream 已保证池条目
// id/token 非空，故 "" 不会是某个合法条目的值。
func (u *Upstream) PickToken(id string) string {
	if len(u.OAuthTokens) == 0 {
		// legacy 单 token：仅默认（空 id）取用；指定 id 在无池下属未命中，不静默回退（治理总纲：错误可见）。
		if id == "" {
			return u.OAuthToken
		}
		return ""
	}
	if id == "" {
		return u.OAuthTokens[0].Token
	}
	for _, t := range u.OAuthTokens {
		if t.ID == id {
			return t.Token
		}
	}
	return ""
}

// parseUpstream 将 JSON 字节解析为 Upstream，校验至少存在一种 token 配置；池条目严格校验
// id/token 非空且 id 不重复，使误配在加载期即暴露（治理总纲：错误可见、禁止静默默认）。
func parseUpstream(b []byte) (*Upstream, error) {
	var u Upstream
	if err := json.Unmarshal(b, &u); err != nil {
		return nil, fmt.Errorf("parse upstream: %w", err)
	}
	if u.OAuthToken == "" && len(u.OAuthTokens) == 0 {
		return nil, fmt.Errorf("upstream.json: no oauthToken(s)")
	}
	seen := make(map[string]bool, len(u.OAuthTokens))
	for i, t := range u.OAuthTokens {
		if t.ID == "" || t.Token == "" {
			return nil, fmt.Errorf("upstream.json: pool entry %d has empty id or token", i)
		}
		if seen[t.ID] {
			return nil, fmt.Errorf("upstream.json: duplicate pool id %q", t.ID)
		}
		seen[t.ID] = true
	}
	return &u, nil
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8788"
	}
	return &c, nil
}

// RequireOwnerOnly 校验 path 仅属主可访问(mode 无 group/other 位)。敏感凭据(setup-token 池 /
// MITM CA 私钥)若 group/other-accessible,同机其他用户或误同步会读到真 token / CA 私钥 →
// fail-closed 拒绝启动(治理总纲:错误可见)。README 要求 upstream.json/ca.key chmod 600。
func RequireOwnerOnly(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s perm %#o too open (group/other-accessible); chmod 600", path, perm)
	}
	return nil
}

func LoadUpstream(path string) (*Upstream, error) {
	if err := RequireOwnerOnly(path); err != nil {
		return nil, fmt.Errorf("upstream perm: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read upstream: %w", err)
	}
	return parseUpstream(b)
}

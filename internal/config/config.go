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
	PublicHost       string `json:"public_host"`       // 代理对外域名 (frp https vhost), 即外层 TLS 身份的 SAN
	FrpsIP           string `json:"frps_ip"`           // frps 公网 IP, 即 helper 直拨 cc-mysub forward-proxy 的入口
	ProxyPort        int    `json:"proxy_port"`        // frp 暴露的 cc-mysub forward-proxy 端口, helper 直拨; 0 = 默认 8788
	SubscriptionType string `json:"subscription_type"` // 你的真实订阅档: pro/max/team/enterprise
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

func LoadUpstream(path string) (*Upstream, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read upstream: %w", err)
	}
	return parseUpstream(b)
}

package hosts

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		host string
		want Class
	}{
		// 精确 MITM(换 token)
		{"api.anthropic.com", MITM},
		{"console.anthropic.com", MITM},
		// 自家后缀:apex + 任意级子域 → passthrough 收口
		{"anthropic.com", Passthrough},
		{"status.anthropic.com", Passthrough},
		{"claude.ai", Passthrough},
		{"foo.claude.ai", Passthrough},
		{"downloads.claude.ai", Passthrough},
		{"claude.com", Passthrough},
		{"slack.mcp.claude.com", Passthrough},
		{"bridge.claudeusercontent.com", Passthrough},
		{"beacon.claude-ai.staging.ant.dev", Passthrough},
		// 精确 passthrough(第三方 host)
		{"http-intake.logs.us5.datadoghq.com", Passthrough},
		{"api.datadoghq.com", Passthrough},
		{"mcp.sentry.dev", Passthrough},
		{"claude.fedstart.com", Passthrough},
		{"claude-staging.fedstart.com", Passthrough},
		// Direct:功能/第三方/用户自配 MCP
		{"github.com", Direct},
		{"registry.npmjs.org", Direct},
		{"mcp.notion.so", Direct}, // 运行时自配 MCP——不在硬编码,C 的固有 gap
		{"datadoghq.com", Direct}, // datadog apex 非自家、不在精确集
		{"fedstart.com", Direct},  // 第三方平台 apex 不收口(只精确 claude.fedstart.com)
		// 后缀边界:防混淆域名误命中
		{"evil-anthropic.com", Direct},
		{"anthropic.com.evil.com", Direct},
	}
	for _, c := range cases {
		if got := Classify(c.host); got != c.want {
			t.Errorf("Classify(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// api.anthropic.com 命中 .anthropic.com 自家后缀,但精确 MITM 必须优先——否则换 token 被降级成
// 盲隧道、占位 token 直达上游。这是 Classify precedence 的关键不变量。
func TestClassify_MITMPrecedenceOverSuffix(t *testing.T) {
	if Classify("api.anthropic.com") != MITM {
		t.Fatal("api.anthropic.com 必须走 MITM,不得被 .anthropic.com 后缀降级为 Passthrough")
	}
}

// 精确 MITM 与精确 passthrough 不相交:一个 host 不能既换 token 又盲透传(否则 forward-proxy 分类
// 歧义)。后缀不参与此检查——精确 MITM 在 Classify 里永远先判,故后缀与 MITM 精确 host 重叠是良性的。
func TestExactSetsDisjoint(t *testing.T) {
	for _, m := range MITMHosts {
		for _, p := range PassthroughExact {
			if m == p {
				t.Errorf("host %q 同时在 MITMHosts 与 PassthroughExact(两精确集必须互斥)", m)
			}
		}
	}
}

func TestIsFirstParty(t *testing.T) {
	first := []string{"anthropic.com", "api.anthropic.com", "foo.claude.ai", "claude.com", "bridge.claudeusercontent.com", "beacon.claude-ai.staging.ant.dev"}
	for _, h := range first {
		if !IsFirstParty(h) {
			t.Errorf("IsFirstParty(%q) = false, want true", h)
		}
	}
	// 第三方(精确收口/直连)与混淆域名不算自家
	third := []string{"api.datadoghq.com", "mcp.sentry.dev", "claude.fedstart.com", "github.com", "evil-anthropic.com"}
	for _, h := range third {
		if IsFirstParty(h) {
			t.Errorf("IsFirstParty(%q) = true, want false", h)
		}
	}
}

// Classify/IsFirstParty 的前置契约是「host 已 DNS 规范化(全小写、无尾点)」。非规范输入必须
// loud-fail(panic),不得静默 miss 成 Direct(自家域名静默降级为直连泄漏 IP)——这是「单一事实源」
// 的收口保证不再悄悄依赖每个调用方先规范化的关键回归守卫。契约是格式而非类别,故第三方/混淆域名的
// 非规范形态同样 panic。
func TestClassify_PanicsOnNonNormalizedHost(t *testing.T) {
	cases := []string{
		"API.ANTHROPIC.COM",  // 全大写
		"Api.Anthropic.Com",  // 混合大小写
		"api.anthropic.com.", // 尾点 FQDN
		"GitHub.com",         // 非自家也须 panic(契约是格式不是类别)
		"github.com.",        // 尾点(非自家)
	}
	for _, h := range cases {
		t.Run(h, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Classify(%q) 未 panic;非规范 host 必须 loud-fail", h)
				}
			}()
			Classify(h)
		})
	}
}

func TestIsFirstParty_PanicsOnNonNormalizedHost(t *testing.T) {
	cases := []string{
		"API.ANTHROPIC.COM",
		"api.anthropic.com.",
		"GitHub.com",
	}
	for _, h := range cases {
		t.Run(h, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("IsFirstParty(%q) 未 panic;非规范 host 必须 loud-fail", h)
				}
			}()
			IsFirstParty(h)
		})
	}
}

// 规范化的合法输入绝不 panic——契约只拒非规范形态,正常收口判定不受影响。
func TestClassify_NormalizedHostDoesNotPanic(t *testing.T) {
	for _, h := range []string{"api.anthropic.com", "anthropic.com", "github.com", "x.y.claude.ai"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Classify(%q) 不应 panic(已规范化): %v", h, r)
				}
			}()
			Classify(h)
			IsFirstParty(h)
		}()
	}
}

func TestMatchSuffix(t *testing.T) {
	cases := []struct {
		host, suffix string
		want         bool
	}{
		{"anthropic.com", "anthropic.com", true},           // apex
		{"x.anthropic.com", "anthropic.com", true},         // 子域
		{"a.b.anthropic.com", "anthropic.com", true},       // 多级子域
		{"evil-anthropic.com", "anthropic.com", false},     // 无 "." 边界
		{"anthropic.com.evil.com", "anthropic.com", false}, // 后缀在中间
		{"notanthropic.com", "anthropic.com", false},
	}
	for _, c := range cases {
		if got := matchSuffix(c.host, c.suffix); got != c.want {
			t.Errorf("matchSuffix(%q,%q) = %v, want %v", c.host, c.suffix, got, c.want)
		}
	}
}

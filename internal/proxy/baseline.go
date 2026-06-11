package proxy

import (
	"net/http"
	"strings"

	"github.com/redcontritio/cc-mysub/internal/auth"
)

// CheckInboundBaseline 返回偏离基线的告警码(不拦截).
func CheckInboundBaseline(r *http.Request) []string {
	var warns []string
	authz := r.Header.Get("Authorization")
	if authz != "" && !strings.HasPrefix(authz, "Bearer ") {
		warns = append(warns, "auth_structure_abnormal")
	}
	if r.Header.Get("X-Api-Key") != "" {
		warns = append(warns, "creds_in_xapikey")
	}
	// missing_oauth_beta 只对带凭据请求有意义:真 Claude Code 的合法匿名请求(registry/遥测)按设计本就
	// 不带 oauth beta 头,对它们告警是常态化噪声、会淹没真信号(P3-3)。带凭据却缺 oauth beta 才是 CC
	// 升级改变认证行为的漂移信号。HasInboundCredential 镜像 ExtractToken 的双头语义(Bearer 或 x-api-key)。
	if auth.HasInboundCredential(r) && !strings.Contains(r.Header.Get("anthropic-beta"), "oauth-2025-04-20") {
		warns = append(warns, "missing_oauth_beta")
	}
	return warns
}

func CheckOutboundBaseline(status int) string {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return "upstream_auth_rejected"
	}
	return ""
}

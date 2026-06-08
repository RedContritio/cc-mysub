package proxy

import (
	"net/http"
	"strings"
)

// CheckInboundBaseline 返回偏离基线的告警码(不拦截).
func CheckInboundBaseline(r *http.Request) []string {
	var warns []string
	auth := r.Header.Get("Authorization")
	if auth != "" && !strings.HasPrefix(auth, "Bearer ") {
		warns = append(warns, "auth_structure_abnormal")
	}
	if r.Header.Get("X-Api-Key") != "" {
		warns = append(warns, "creds_in_xapikey")
	}
	if !strings.Contains(r.Header.Get("anthropic-beta"), "oauth-2025-04-20") {
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

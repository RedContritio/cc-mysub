package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
)

var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ExtractToken(r *http.Request) string {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimSpace(a[len("Bearer "):])
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key"))
}

func HashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// CertFingerprint 返回客户端证书 DER 的 SHA-256，小写 hex（64 字符）。
// 这是 devices.json 的 cert_sha256 与 VerifyPeerCertificate 现算值的唯一规范形。
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]) // hex.EncodeToString 产小写
}

// CanonicalFingerprint 报告 s 是否为规范指纹（恰 64 位小写 hex）。
func CanonicalFingerprint(s string) bool { return fingerprintRE.MatchString(s) }

// HasInboundCredential 报告入站请求是否携带任一凭据（非空 Authorization: Bearer 或非空 X-Api-Key）。
// 镜像 ExtractToken 的双头语义，供 conditionalAuth 的"换 token vs 匿名透传"分流——
// 收窄成只看 Authorization 会把 X-Api-Key-only 请求误判匿名（治理回归）。
func HasInboundCredential(r *http.Request) bool {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") && strings.TrimSpace(a[len("Bearer "):]) != "" {
		return true
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key")) != ""
}

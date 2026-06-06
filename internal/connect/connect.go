// Package connect 解析与校验 HTTP CONNECT 目标，供 forward-proxy 与设备分流器共用。
package connect

import (
	"net"
	"strings"
)

// ParseConnect 解析 HTTP CONNECT 请求行，返回校验后的目标 host（不含端口）。
// ok=false 表示非 CONNECT 行、缺 host:port、或 host 非法。因返回的 host 直接
// 用于现签叶证书，故拒绝控制字符/通配符/空 host 等可被注入证书的输入。
func ParseConnect(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "CONNECT" {
		return "", false
	}
	host, _, err := net.SplitHostPort(fields[1])
	if err != nil {
		return "", false
	}
	if !ValidHost(host) {
		return "", false
	}
	return host, true
}

// ValidHost 接受合法裸主机名或 IP 字面量；拒绝空、过长、含非主机名字符
// （含控制字符、空格、通配符 '*'）的输入。
func ValidHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

// 注：信道 token 子系统已删除（mTLS 客户端证书取代）。原 ParseProxyAuthorization /
// ValidToken 随之移除——设备身份由外层 mTLS 证书指纹承载，CONNECT 头不再带 Proxy-Authorization。

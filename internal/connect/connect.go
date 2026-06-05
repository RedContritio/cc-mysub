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

// ParseProxyAuthorization 解析单条 CONNECT 头行,提取信道层 Bearer token。
// 头名须 EqualFold 精确等于 "Proxy-Authorization"(拒前缀/后缀影射如
// X-Proxy-Authorization / Proxy-Authorization-Foo,拒名与冒号间空白);scheme 须
// Bearer(大小写不敏感)。token 空/全空白/含内部空格/控制字符/CR/LF/NUL/非可打印
// → ok=false(空为硬不变量,不委托上层 Lookup,镜像 ValidHost 白名单)。
//
// 调用方(forward.go)用 br.ReadString('\n') 读头,行尾带 \r\n,故先剥恰一个行尾
// 终止符;剥后任何内部 CR/LF 视为注入,拒。
func ParseProxyAuthorization(headerLine string) (string, bool) {
	line := headerLine
	if strings.HasSuffix(line, "\r\n") {
		line = strings.TrimSuffix(line, "\r\n")
	} else if strings.HasSuffix(line, "\n") {
		line = strings.TrimSuffix(line, "\n")
	}
	// 剥行尾后,任何残留 CR/LF 都是注入(如 "Bearer a\rb")。
	if strings.ContainsAny(line, "\r\n") {
		return "", false
	}

	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", false
	}
	name := line[:i]
	// 拒名与冒号间空白(如 "Proxy-Authorization "):名末位不得为 SP/TAB。
	if name == "" || name[len(name)-1] == ' ' || name[len(name)-1] == '\t' {
		return "", false
	}
	if !strings.EqualFold(name, "Proxy-Authorization") {
		return "", false
	}

	val := line[i+1:]
	// 标准头 OWS:恰剥一个可选前导 SP(Go/客户端发出的规范形)。
	if strings.HasPrefix(val, " ") {
		val = val[1:]
	}
	// scheme = 首个 SP 前的子串;须 EqualFold "Bearer"。须存在分隔 SP 与 token。
	sp := strings.IndexByte(val, ' ')
	if sp < 0 {
		return "", false // "Bearer"(无值无空格) / 无 scheme
	}
	if !strings.EqualFold(val[:sp], "Bearer") {
		return "", false
	}
	token := val[sp+1:]
	if !ValidToken(token) {
		return "", false
	}
	return token, true
}

// ValidToken 接受非空、仅含 token-合法可打印 ASCII 的 token;拒空、空格、TAB、
// 控制字符、NUL、非 ASCII。字符集为 ValidHost 白名单的 token 超集(加 _ ~ + / = .)。
// 同时供 splitter.New 在构造时验证信道 token，保证两端字符集完全一致。
func ValidToken(t string) bool {
	if t == "" {
		return false
	}
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_', r == '~', r == '+', r == '/', r == '=':
		default:
			return false
		}
	}
	return true
}

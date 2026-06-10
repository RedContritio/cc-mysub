package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/redcontritio/cc-mysub/internal/splitter"
)

// runHelper は `cc-mysub helper` 子命令：绑本地 CONNECT 分流器 + 注入 HTTPS_PROXY + exec claude。
// 外层走 mTLS（出示本设备客户端证书）+ 系统信任验真 LE；身份由证书承载，无需 CA/信道 token。
// 返回子进程退出码（出错返回非 0）。
func runHelper(args []string) int {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	var (
		host       = fs.String("host", "", "cc-mysub 域名 host（拨 host:443 + 外层 TLS ServerName，必填）")
		clientCert = fs.String("client-cert", "", "本设备客户端证书路径（device-init 生成，必填）")
		clientKey  = fs.String("client-key", "", "本设备私钥路径（device-init 生成，必填）")
		// 收口集由 internal/hosts.Classify 权威裁决（与 cc-mysub 侧同源，避免两端漂移）：自家域名后缀
		// 通配 + 第三方精确收口，其余本地直连。--allow 仅用于在该集之外额外强制 chain 个别 host
		// （默认空；非清单 host 即便 chain 到 cc-mysub 也会被其 allowlist 403）。
		allowCSV = fs.String("allow", "", "在默认收口集之外额外强制经 cc-mysub 收口的 host（逗号分隔）")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	childArgs := fs.Args() // `--` 之后的 claude argv
	if *host == "" || *clientCert == "" || *clientKey == "" || len(childArgs) == 0 {
		fmt.Fprintln(os.Stderr, "用法: cc-mysub helper --host HOST --client-cert device.crt --client-key device.key -- claude [args...]")
		return 2
	}

	// 加载本设备客户端证书+私钥（外层 mTLS 出示）；缺失/坏 → fail-closed（先跑 device-init）。
	cert, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载设备证书/私钥: %v（先跑 cc-mysub device-init）\n", err)
		return 2
	}

	// 绑 localhost 分流器
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "监听: %v\n", err)
		return 2
	}
	defer ln.Close()

	var extra []string
	if *allowCSV != "" {
		extra = strings.Split(*allowCSV, ",")
	}
	sp := splitter.New(*host, cert, extra, nil)
	go sp.Serve(ln) //nolint:errcheck

	// exec claude，注入 HTTPS_PROXY 指向本地分流器
	proxyURL := "http://" + ln.Addr().String()
	cmd := exec.Command(childArgs[0], childArgs[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = proxyEnv(os.Environ(), proxyURL)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "启动 claude: %v\n", err)
		return 1
	}
	return 0
}

// proxyEnv 返回让 claude 走本地 splitter 的环境:先剔除可能绕过 splitter 的代理变量(NO_PROXY 直连
// 豁免、任意大小写的 *_proxy),再注入权威大写值。否则环境残留 NO_PROXY=anthropic.com 或小写
// https_proxy 会让自家流量静默绕过收口、泄漏设备真实 IP(codex 全仓审查 P2-5)。
func proxyEnv(base []string, proxyURL string) []string {
	out := make([]string, 0, len(base)+4)
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(k) {
		case "NO_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY":
			continue
		}
		out = append(out, kv)
	}
	return append(out,
		"HTTPS_PROXY="+proxyURL,
		"HTTP_PROXY="+proxyURL,
		"ALL_PROXY="+proxyURL,
		"NODE_USE_ENV_PROXY=1",
	)
}

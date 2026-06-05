package main

import (
	"crypto/x509"
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
// 返回子进程退出码（出错返回非 0）。
func runHelper(args []string) int {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	var (
		upstream   = fs.String("upstream", "", "cc-mysub forward-proxy 入口 host:port（必填）")
		caPath     = fs.String("ca", "", "cc-mysub CA 公证书路径（验证外层身份，必填）")
		serverName = fs.String("server-name", "", "cc-mysub 外层 TLS 身份（public_host，必填）")
		allowCSV   = fs.String("allow", "api.anthropic.com,console.anthropic.com", "链到 cc-mysub 的 host（逗号分隔）")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	childArgs := fs.Args() // `--` 之后的 claude argv
	if *upstream == "" || *caPath == "" || *serverName == "" || len(childArgs) == 0 {
		fmt.Fprintln(os.Stderr, "用法: cc-mysub helper --upstream H:P --ca ca.crt --server-name HOST -- claude [args...]")
		return 2
	}

	// 读 CA 公证书 → pool
	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读 CA: %v\n", err)
		return 2
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		fmt.Fprintln(os.Stderr, "CA 证书无效")
		return 2
	}

	// 绑 localhost 分流器
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "监听: %v\n", err)
		return 2
	}
	defer ln.Close()

	allow := strings.Split(*allowCSV, ",")
	sp, err := splitter.New(*upstream, pool, os.Getenv("CLAUDE_CODE_OAUTH_TOKEN"), *serverName, allow, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "分流器初始化: %v\n", err)
		return 2
	}
	go sp.Serve(ln) //nolint:errcheck

	// exec claude，注入 HTTPS_PROXY 指向本地分流器
	proxyURL := "http://" + ln.Addr().String()
	cmd := exec.Command(childArgs[0], childArgs[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(),
		"HTTPS_PROXY="+proxyURL,
		"HTTP_PROXY="+proxyURL,
		"ALL_PROXY="+proxyURL,
		"NODE_USE_ENV_PROXY=1",
	)
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

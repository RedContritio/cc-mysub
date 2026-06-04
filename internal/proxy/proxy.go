package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type Proxy struct {
	upstream *url.URL
	rp       *httputil.ReverseProxy
}

// New 构造代理: 所有请求转发到 upstreamBaseURL, Authorization 换成 Bearer oauthToken.
func New(upstreamBaseURL, oauthToken string) (*Proxy, error) {
	u, err := url.Parse(upstreamBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream url: %w", err)
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)     // scheme/host -> 上游; 保留 path+query
			pr.Out.Host = "" // 用上游 host
			pr.Out.Header.Set("Authorization", "Bearer "+oauthToken)
			pr.Out.Header.Del("X-Api-Key")
		},
		// 瞬态网络错误重试 2 次 (spec §9)
		Transport: &retryTransport{base: http.DefaultTransport, delays: []time.Duration{0, 200 * time.Millisecond, 600 * time.Millisecond}},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":{"code":"upstream_error","message":"upstream request failed"}}`))
		},
	}
	return &Proxy{upstream: u, rp: rp}, nil
}

// Handler 返回裸转发 handler (Milestone 1; 后续里程碑在外层包中间件).
func (p *Proxy) Handler() http.Handler {
	return p.rp
}

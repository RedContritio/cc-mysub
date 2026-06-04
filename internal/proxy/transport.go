package proxy

import (
	"net/http"
	"time"
)

// retryTransport 对网络层错误(非 HTTP 状态码错误)按 delays 重试.
type retryTransport struct {
	base   http.RoundTripper
	delays []time.Duration
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	for i, d := range t.delays {
		if d > 0 {
			time.Sleep(d)
		}
		resp, err = t.base.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		_ = i
	}
	return resp, err
}

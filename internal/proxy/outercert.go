package proxy

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

// NewOuterCertLoader 返回一个 tls.Config.GetCertificate 闭包，加载外层 TLS 身份证书（真 LE），
// 按 cert 文件 mtime 缓存并在续期后热重载——使 LE 续期无需重启 cc-mysub。
func NewOuterCertLoader(certPath, keyPath string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l := &outerCertLoader{certPath: certPath, keyPath: keyPath}
	return l.get
}

type outerCertLoader struct {
	certPath, keyPath string
	mu                sync.RWMutex
	cached            *tls.Certificate
	mod               time.Time
}

func (l *outerCertLoader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	fi, err := os.Stat(l.certPath)
	if err != nil {
		return nil, fmt.Errorf("stat outer cert: %w", err)
	}
	l.mu.RLock()
	cached, mod := l.cached, l.mod
	l.mu.RUnlock()
	if cached != nil && !fi.ModTime().After(mod) {
		return cached, nil
	}
	pair, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load outer cert: %w", err)
	}
	l.mu.Lock()
	l.cached, l.mod = &pair, fi.ModTime()
	l.mu.Unlock()
	return &pair, nil
}

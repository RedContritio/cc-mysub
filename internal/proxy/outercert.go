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
	size              int64
}

func (l *outerCertLoader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	fi, err := os.Stat(l.certPath)
	if err != nil {
		return nil, fmt.Errorf("stat outer cert: %w", err)
	}
	l.mu.RLock()
	cached, mod, size := l.cached, l.mod, l.size
	l.mu.RUnlock()
	// 任何 mtime 变化或文件大小变化都重载——用 Equal 而非 After()。After() 只识别 mtime 严格前移,会让
	// 续期失败后从备份恢复旧证书(cp -p/rsync -a/tar 还原保留较旧 mtime,mtime 回退)或同 mtime 粒度内的
	// 替换永远命中缓存、返回内存里的坏/过期证书,零信号直到进程重启(P2-61/P3-65)。mtime+size 覆盖现实的
	// 续期/回滚/恢复;残留盲点(同 mtime 同 size 异内容)对真实 LE 证书概率可忽略。
	// 已知粗糙点:只 stat cert,单独换 key 不触发重载;但 cert/key 总是成对续期,且不匹配对会在下次重载
	// LoadX509KeyPair 时 loud-fail。
	if cached != nil && fi.ModTime().Equal(mod) && fi.Size() == size {
		return cached, nil
	}
	pair, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load outer cert: %w", err)
	}
	l.mu.Lock()
	l.cached, l.mod, l.size = &pair, fi.ModTime(), fi.Size()
	l.mu.Unlock()
	return &pair, nil
}

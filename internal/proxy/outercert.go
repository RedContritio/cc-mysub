package proxy

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/redcontritio/cc-mysub/internal/config"
)

// NewOuterCertLoader 返回一个 tls.Config.GetCertificate 闭包，加载外层 TLS 身份证书（真 LE），
// 按 cert+key 的 mtime/size 缓存,并每次握手校验 key 权限位——使 LE 续期无需重启 cc-mysub。
func NewOuterCertLoader(certPath, keyPath string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l := &outerCertLoader{certPath: certPath, keyPath: keyPath}
	return l.get
}

type outerCertLoader struct {
	certPath, keyPath string
	mu                sync.RWMutex
	cached            *tls.Certificate
	mod, keyMod       time.Time
	size, keySize     int64
}

func (l *outerCertLoader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cfi, err := os.Stat(l.certPath)
	if err != nil {
		return nil, fmt.Errorf("stat outer cert: %w", err)
	}
	kfi, err := os.Stat(l.keyPath)
	if err != nil {
		return nil, fmt.Errorf("stat outer key: %w", err)
	}
	// 私钥权限每次握手都校验(复用上面这份 stat,零额外开销),且不挂在缓存失效路径上:
	// chmod 只改 ctime 不改 mtime/size,就地放宽权限永远不触发重载判定;只在启动校验一次
	// 的权限门会随续期/误操作在长跑进程上衰减(Backlog P2)。fail-closed:握手期权限错误
	// =该次握手失败(loud,可见),收紧回 0600 即恢复。
	// 残留边界:(a) stat→LoadX509KeyPair 之间的窗口内 key 被放宽,本次握手仍用已读内容,
	// 下一次 get() 即拒——暴露上界=单次握手;(b) os.Stat 跟随 symlink,校验的是目标文件权限
	// (certbot live/→archive/ 布局下正确:symlink 自身 0777 无意义,密钥实体是目标)。
	if err := config.OwnerOnly(kfi, l.keyPath); err != nil {
		return nil, fmt.Errorf("outer key perm: %w", err)
	}
	l.mu.RLock()
	cached, mod, size, keyMod, keySize := l.cached, l.mod, l.size, l.keyMod, l.keySize
	l.mu.RUnlock()
	// 任何 mtime 变化或文件大小变化都重载——用 Equal 而非 After()。After() 只识别 mtime 严格前移,会让
	// 续期失败后从备份恢复旧证书(cp -p/rsync -a/tar 还原保留较旧 mtime,mtime 回退)或同 mtime 粒度内的
	// 替换永远命中缓存、返回内存里的坏/过期证书,零信号直到进程重启(P2-61/P3-65)。mtime+size 覆盖现实的
	// 续期/回滚/恢复;残留盲点(同 mtime 同 size 异内容)对真实 LE 证书概率可忽略。
	// key 同样纳入判定(Backlog P2):单独换 key 触发重载,不匹配对 LoadX509KeyPair loud-fail——
	// 续期两文件非原子落盘的间隙是瞬时失败(客户端重试自愈),优于旧行为的磁盘/内存无限期静默漂移。
	if cached != nil && cfi.ModTime().Equal(mod) && cfi.Size() == size &&
		kfi.ModTime().Equal(keyMod) && kfi.Size() == keySize {
		return cached, nil
	}
	pair, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load outer cert: %w", err)
	}
	l.mu.Lock()
	l.cached, l.mod, l.size, l.keyMod, l.keySize = &pair, cfi.ModTime(), cfi.Size(), kfi.ModTime(), kfi.Size()
	l.mu.Unlock()
	return &pair, nil
}

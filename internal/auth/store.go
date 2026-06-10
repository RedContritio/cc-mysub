package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

type Device struct {
	Label      string `json:"label"`
	CertSHA256 string `json:"cert_sha256"` // 客户端证书 SHA-256(DER) 小写 hex; 设备身份
	RateLimit  int    `json:"rate_limit"`  // 每分钟请求数; 0 = 用默认
	Upstream   string `json:"upstream"`    // 所属 setup-token id; 空 = 使用默认 token
}

type DeviceStore struct {
	path         string
	pollInterval time.Duration

	mu      sync.RWMutex
	byHash  map[string]Device
	lastMod time.Time

	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	onRevoke func([]string) // 被删除(吊销)的 fingerprint 回调;reload 检测到删除时调(P1-2)
}

func NewDeviceStore(path string) (*DeviceStore, error) {
	s := &DeviceStore{path: path, pollInterval: time.Second, stop: make(chan struct{})}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *DeviceStore) reload() error {
	fi, err := os.Stat(s.path)
	if err != nil {
		return fmt.Errorf("stat devices: %w", err)
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read devices: %w", err)
	}
	var list []Device
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("parse devices: %w", err)
	}
	m := make(map[string]Device, len(list))
	for _, d := range list {
		if !CanonicalFingerprint(d.CertSHA256) {
			// 非规范行（空 / 非 64-lowercase-hex，多来自手编或损坏）永不进表；大声 surface，
			// 不静默吞——否则被丢行的设备只表现为外层握手失败、两端皆无日志，「错误可见」成空话。
			slog.Warn("devices: dropping row with non-canonical cert_sha256",
				"label", d.Label, "cert_sha256", d.CertSHA256)
			continue
		}
		if prev, dup := m[d.CertSHA256]; dup {
			// 同一指纹多行 = 同一设备多别名：拒载整个文件（不做 last-wins），保留旧表。否则按
			// label 吊销会假成功，而该指纹经另一行仍被授权——吊销契约 fail-open（错误可见、fail-closed）。
			return fmt.Errorf("devices: duplicate cert_sha256 %s (labels %q and %q); refusing to load",
				d.CertSHA256, prev.Label, d.Label)
		}
		if d.RateLimit < 0 {
			// 负 rate_limit 只来自手编 devices.json（CLI 的 Resolve 在登记期已拒负值）。非安全不变量
			// （middleware 只采信 >0），故大声告警并归零到代理默认而非拒载整个文件——避免一处 typo 锁死整个 fleet。
			slog.Warn("devices: negative rate_limit coerced to proxy default",
				"label", d.Label, "rate_limit", d.RateLimit)
			d.RateLimit = 0
		}
		m[d.CertSHA256] = d
	}
	s.mu.Lock()
	old := s.byHash
	s.byHash = m
	s.lastMod = fi.ModTime()
	cb := s.onRevoke
	s.mu.Unlock()

	// diff:旧表有、新表无的 fingerprint = 被吊销 → 回调(forward-proxy 关其既有外层连接,P1-2 即时吊销)。
	// 锁外调,避免回调里再触及 store 造成重入。首次 reload(old==nil)无 diff。
	if cb != nil && old != nil {
		var removed []string
		for fp := range old {
			if _, ok := m[fp]; !ok {
				removed = append(removed, fp)
			}
		}
		if len(removed) > 0 {
			cb(removed)
		}
	}
	return nil
}

// SetOnRevoke 注册「fingerprint 从 devices.json 删除(吊销)」的回调,reload 检测到删除时调用。
// 用于 P1-2:让 forward-proxy 主动断开被吊销设备的既有外层连接,使吊销即时生效。须在 StartWatch 前设。
func (s *DeviceStore) SetOnRevoke(f func([]string)) {
	s.mu.Lock()
	s.onRevoke = f
	s.mu.Unlock()
}

// Lookup 按客户端证书指纹（SHA-256(DER) 小写 hex）直接查白名单。fp 已是 digest，
// 不二次哈希——否则键 != cert_sha256，全量静默认证失败。
func (s *DeviceStore) Lookup(fp string) (Device, bool) {
	if !CanonicalFingerprint(fp) {
		return Device{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.byHash[fp]
	return d, ok
}

func (s *DeviceStore) StartWatch() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(s.pollInterval)
		defer t.Stop()
		statFailing := false // 状态翻转去重：stat 持续失败时仅在进入/恢复各记一条，避免每秒刷屏。
		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				fi, err := os.Stat(s.path)
				if err != nil {
					// stat 失败（文件被删 / 目录被挪 / 权限破坏）与 reload 失败同源：旧表继续
					// 生效，但操作者必须可见——否则 `rm devices.json` 这类「紧急全撤销」直觉动作后，
					// 全部设备无限期沿用旧授权且零信号（错误可见、fail-closed）。
					if !statFailing {
						slog.Error("devices stat failed; keeping previous table", "path", s.path, "err", err)
						statFailing = true
					}
					continue
				}
				if statFailing {
					slog.Info("devices stat recovered", "path", s.path)
					statFailing = false
				}
				s.mu.RLock()
				// !Equal 而非 After：同时覆盖「同 mtime 二次写」与「mtime 回退（cp -p/rsync -a
				// 从备份恢复，时间戳变旧）」——After 会漏掉回退（旧 mtime 永不 > lastMod），使恢复
				// 意图静默不生效直至重启。
				changed := !fi.ModTime().Equal(s.lastMod)
				s.mu.RUnlock()
				if changed {
					if err := s.reload(); err != nil {
						// 保留旧表，但大声 surface 失败：手滑改坏 devices.json 不得静默不撤销。
						slog.Error("devices reload failed; keeping previous table", "err", err)
					}
				}
			}
		}
	}()
}

// StopWatch signals the background goroutine to stop and blocks until it exits.
// Safe to call multiple times (subsequent calls are no-ops after the first).
func (s *DeviceStore) StopWatch() {
	s.closeOnce.Do(func() { close(s.stop) })
	s.wg.Wait()
}

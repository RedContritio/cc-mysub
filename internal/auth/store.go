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
			continue // 拒空/非 64-lowercase-hex 行（错误可见，永不进表）
		}
		m[d.CertSHA256] = d
	}
	s.mu.Lock()
	s.byHash = m
	s.lastMod = fi.ModTime()
	s.mu.Unlock()
	return nil
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
		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				fi, err := os.Stat(s.path)
				if err != nil {
					continue
				}
				s.mu.RLock()
				changed := fi.ModTime().After(s.lastMod)
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

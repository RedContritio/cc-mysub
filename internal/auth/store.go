package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// emptyTokenHash is the sha256 of the empty token. A devices.json row carrying
// this digest can only ever be matched by an empty presented token, which is
// itself rejected at Lookup's entry — so such a row is always inert. Reject it
// at load so it never even occupies a map slot.
var emptyTokenHash = HashToken("")

type Device struct {
	Label       string `json:"label"`
	TokenSHA256 string `json:"token_sha256"`
	RateLimit   int    `json:"rate_limit"` // 每分钟请求数; 0 = 用默认
	Upstream    string `json:"upstream"`   // 所属 setup-token id; 空 = 使用默认 token
}

type DeviceStore struct {
	path         string
	pollInterval time.Duration

	mu      sync.RWMutex
	byHash  map[string]Device
	lastMod time.Time

	stop chan struct{}
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
		if d.TokenSHA256 == "" || d.TokenSHA256 == emptyTokenHash {
			continue
		}
		m[d.TokenSHA256] = d
	}
	s.mu.Lock()
	s.byHash = m
	s.lastMod = fi.ModTime()
	s.mu.Unlock()
	return nil
}

func (s *DeviceStore) Lookup(token string) (Device, bool) {
	if token == "" {
		return Device{}, false
	}
	h := HashToken(token)
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.byHash[h]
	return d, ok
}

func (s *DeviceStore) StartWatch() {
	go func() {
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

func (s *DeviceStore) StopWatch() { close(s.stop) }

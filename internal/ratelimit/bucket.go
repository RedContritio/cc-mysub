package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

type Limiter struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]*bucket
}

func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, m: make(map[string]*bucket)}
}

// Allow: perMinute 为该 device 每分钟配额(也是 burst 上限). perMinute<=0 视为不限.
func (l *Limiter) Allow(device string, perMinute int) bool {
	if perMinute <= 0 {
		return true
	}
	ratePerSec := float64(perMinute) / 60.0
	burst := float64(perMinute)

	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.m[device]
	if !ok {
		b = &bucket{tokens: burst, last: now}
		l.m[device] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * ratePerSec
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

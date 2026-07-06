package runtime

import "sync"

type RateLimiter struct {
	mu    sync.Mutex
	limit int
	seen  map[string]int
}

func NewRateLimiter(limit int) *RateLimiter {
	if limit < 1 {
		limit = 1
	}
	return &RateLimiter{
		limit: limit,
		seen:  map[string]int{},
	}
}

func (l *RateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.seen[key] >= l.limit {
		return false
	}
	l.seen[key]++
	return true
}

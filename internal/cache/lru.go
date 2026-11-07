// Package cache is a small bounded LRU with per-entry expiry and coalesced misses.
package cache

import (
	"container/list"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type entry[V any] struct {
	key     string
	value   V
	expires time.Time
}

// LRU holds at most Max entries; the least recently used entry is evicted first.
type LRU[V any] struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	order *list.List
	items map[string]*list.Element
	group singleflight.Group
	now   func() time.Time

	Hits, Misses, Evictions int64
}

// New returns an LRU with capacity max (at least 1) and entry lifetime ttl (0: no expiry).
func New[V any](max int, ttl time.Duration) *LRU[V] {
	return &LRU[V]{max: maxInt(1, max), ttl: ttl, order: list.New(), items: map[string]*list.Element{}, now: time.Now}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Stats returns hit, miss and eviction counts.
func (c *LRU[V]) Stats() (hits, misses, evictions int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Hits, c.Misses, c.Evictions
}

// Get returns a live entry.
func (c *LRU[V]) Get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry[V])
		if c.ttl == 0 || c.now().Before(e.expires) {
			c.order.MoveToFront(el)
			c.Hits++
			return e.value, true
		}
		c.order.Remove(el)
		delete(c.items, key)
	}
	c.Misses++
	var zero V
	return zero, false
}

// Put stores an entry, evicting the least recently used one when full.
func (c *LRU[V]) Put(key string, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry[V])
		e.value, e.expires = v, c.now().Add(c.ttl)
		c.order.MoveToFront(el)
		return
	}
	c.items[key] = c.order.PushFront(&entry[V]{key: key, value: v, expires: c.now().Add(c.ttl)})
	for c.order.Len() > c.max {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.items, last.Value.(*entry[V]).key)
		c.Evictions++
	}
}

// GetOrLoad returns the cached value or calls load once for all concurrent callers of the same key.
func (c *LRU[V]) GetOrLoad(key string, load func() (V, error)) (V, error) {
	if v, ok := c.Get(key); ok {
		return v, nil
	}
	v, err, _ := c.group.Do(key, func() (any, error) {
		if v, ok := c.Get(key); ok {
			return v, nil
		}
		v, err := load()
		if err == nil {
			c.Put(key, v)
		}
		return v, err
	})
	if err != nil {
		var zero V
		return zero, err
	}
	return v.(V), nil
}

// Len is the number of entries (including expired ones not yet evicted).
func (c *LRU[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// Clear drops everything.
func (c *LRU[V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order.Init()
	c.items = map[string]*list.Element{}
}

package cache

import (
	"sync"
	"time"
)

type item struct {
	value      interface{}
	expiration time.Time
}

type Cache struct {
	mu     sync.RWMutex
	items  map[string]item
	ttl    time.Duration
	stopCh chan struct{}
}

func New(ttl time.Duration) *Cache {
	c := &Cache{
		items:  make(map[string]item),
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}
	go c.cleanup()
	return c
}

func (c *Cache) Stop() {
	close(c.stopCh)
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	it, ok := c.items[key]
	if !ok || time.Now().After(it.expiration) {
		return nil, false
	}
	return it.value, true
}

func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = item{
		value:      value,
		expiration: time.Now().Add(c.ttl),
	}
}

func (c *Cache) cleanup() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for k, v := range c.items {
				if now.After(v.expiration) {
					delete(c.items, k)
				}
			}
			c.mu.Unlock()
		case <-c.stopCh:
			return
		}
	}
}

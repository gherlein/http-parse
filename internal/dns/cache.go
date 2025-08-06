package dns

import (
	"strings"
	"sync"
)

type Cache struct {
	mu      sync.RWMutex
	entries map[string]string // IP -> FQDN mapping
}

func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]string),
	}
}

func (c *Cache) Add(ip, fqdn string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[ip] = strings.TrimSuffix(fqdn, ".")
}

func (c *Cache) Get(ip string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	fqdn, ok := c.entries[ip]
	return fqdn, ok
}

func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

type Cache struct {
	mu       sync.RWMutex
	entries  map[string]string // IP -> FQDN mapping
	rdnsCache map[string]string // IP -> reverse DNS hostname mapping
}

func NewCache() *Cache {
	return &Cache{
		entries:   make(map[string]string),
		rdnsCache: make(map[string]string),
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

// GetWithRDNS attempts to get FQDN from DNS cache first, then performs reverse DNS lookup
func (c *Cache) GetWithRDNS(ip string) string {
	// First check DNS cache for forward DNS resolution
	if fqdn, ok := c.Get(ip); ok {
		return fqdn
	}
	
	// Then check reverse DNS cache
	c.mu.RLock()
	if hostname, ok := c.rdnsCache[ip]; ok {
		c.mu.RUnlock()
		return hostname
	}
	c.mu.RUnlock()
	
	// Perform reverse DNS lookup with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		// Cache negative result to avoid repeated lookups
		c.mu.Lock()
		c.rdnsCache[ip] = ""
		c.mu.Unlock()
		return ""
	}
	
	// Use the first hostname and remove trailing dot
	hostname := strings.TrimSuffix(names[0], ".")
	
	// Cache the result
	c.mu.Lock()
	c.rdnsCache[ip] = hostname
	c.mu.Unlock()
	
	return hostname
}

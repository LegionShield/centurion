package statusdb

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
)

type Item struct {
	Domain      string
	Dns         string
	Time        time.Time
	Retry       int
	DomainLevel int
}

// StatusDb
type StatusDb struct {
	shards     []*DbShard
	shardCount int
	length     int64
	expiration time.Duration
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// DbShard
type DbShard struct {
	items map[string]*Item
	mu    sync.RWMutex
}

// CreateMemoryDB
func CreateMemoryDB() *StatusDb {
	shardCount := 64
	db := &StatusDb{
		shards:          make([]*DbShard, shardCount),
		shardCount:      shardCount,
		length:          0,
		expiration:      5 * time.Minute,
		cleanupInterval: 3 * time.Minute,
		stopCleanup:     make(chan struct{}),
	}

	for i := 0; i < shardCount; i++ {
		db.shards[i] = &DbShard{
			items: make(map[string]*Item),
		}
	}

	go db.startCleanupTimer()

	return db
}

func (r *StatusDb) startCleanupTimer() {
	ticker := time.NewTicker(r.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.cleanup()
		case <-r.stopCleanup:
			return
		}
	}
}

func (r *StatusDb) cleanup() {
	now := time.Now()
	threshold := now.Add(-r.expiration)

	for _, shard := range r.shards {
		shard.mu.Lock()
		for domain, item := range shard.items {
			if item.Time.Before(threshold) {
				delete(shard.items, domain)
				atomic.AddInt64(&r.length, -1)
			}
		}
		shard.mu.Unlock()
	}
}

// SetExpiration
func (r *StatusDb) SetExpiration(d time.Duration) {
	r.expiration = d
}

// getShard
func (r *StatusDb) getShard(domain string) *DbShard {
	// xxhash:
	hash := xxhash.Sum64String(domain)
	return r.shards[hash%uint64(r.shardCount)]
}

// Add
func (r *StatusDb) Add(domain string, tableData Item) {
	shard := r.getShard(domain)
	shard.mu.Lock()
	_, exists := shard.items[domain]
	if !exists {
		atomic.AddInt64(&r.length, 1)
		itemCopy := tableData
		shard.items[domain] = &itemCopy
	} else {
		*(shard.items[domain]) = tableData
	}
	shard.mu.Unlock()
}

// Set
func (r *StatusDb) Set(domain string, tableData Item) {
	shard := r.getShard(domain)
	shard.mu.Lock()
	if _, exists := shard.items[domain]; !exists {
		atomic.AddInt64(&r.length, 1)
		itemCopy := tableData
		shard.items[domain] = &itemCopy
	} else {
		*(shard.items[domain]) = tableData
	}
	shard.mu.Unlock()
}

// Get
func (r *StatusDb) Get(domain string) (Item, bool) {
	shard := r.getShard(domain)
	shard.mu.RLock()
	item, ok := shard.items[domain]
	var result Item
	if ok {
		result = *item
	}
	shard.mu.RUnlock()
	return result, ok
}

// Length
func (r *StatusDb) Length() int64 {
	return atomic.LoadInt64(&r.length)
}

// Del
func (r *StatusDb) Del(domain string) {
	shard := r.getShard(domain)
	shard.mu.Lock()
	_, ok := shard.items[domain]
	if ok {
		delete(shard.items, domain)
		atomic.AddInt64(&r.length, -1)
	}
	shard.mu.Unlock()
}

// Scan
func (r *StatusDb) Scan(f func(key string, value Item) error) {
	if f == nil {
		return
	}

	allItems := make(map[string]Item)

	for _, shard := range r.shards {
		shard.mu.RLock()
		for k, v := range shard.items {
			if v != nil {
				allItems[k] = *v
			}
		}
		shard.mu.RUnlock()
	}

	for k, v := range allItems {
		if err := f(k, v); err != nil {
			continue
		}
	}
}

// Close
func (r *StatusDb) Close() {
	close(r.stopCleanup)

	for _, shard := range r.shards {
		shard.mu.Lock()
		shard.items = nil
		shard.mu.Unlock()
	}
}

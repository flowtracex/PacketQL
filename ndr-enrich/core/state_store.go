package core

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// StateStoreConfig is kept for backward compatibility with existing config files.
type StateStoreConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Database int    `json:"database"`
	PoolSize int    `json:"pool_size"`
}

type localStringCmd struct {
	value string
	err   error
}

func (c *localStringCmd) Result() (string, error) {
	return c.value, c.err
}

type localIntCmd struct {
	value int64
	err   error
}

func (c *localIntCmd) Result() (int64, error) {
	return c.value, c.err
}

type localStatusCmd struct {
	err error
}

func (c *localStatusCmd) Err() error {
	return c.err
}

type localStore struct {
	mu      sync.Mutex
	values  map[string]string
	hashes  map[string]map[string]string
	sets    map[string]map[string]struct{}
	counter map[string]int64
}

func newLocalStore() *localStore {
	return &localStore{
		values:  make(map[string]string),
		hashes:  make(map[string]map[string]string),
		sets:    make(map[string]map[string]struct{}),
		counter: make(map[string]int64),
	}
}

type localStateStoreClient struct {
	store *localStore
}

func (c *localStateStoreClient) Get(_ context.Context, key string) *localStringCmd {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	value, ok := c.store.values[key]
	if !ok {
		return &localStringCmd{err: fmt.Errorf("key not found")}
	}
	return &localStringCmd{value: value}
}

func (c *localStateStoreClient) Set(_ context.Context, key string, value interface{}, _ time.Duration) *localStatusCmd {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	c.store.values[key] = fmt.Sprint(value)
	return &localStatusCmd{}
}

func (c *localStateStoreClient) Incr(_ context.Context, key string) *localIntCmd {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	c.store.counter[key]++
	return &localIntCmd{value: c.store.counter[key]}
}

func (c *localStateStoreClient) HGet(_ context.Context, key, field string) *localStringCmd {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	fields, ok := c.store.hashes[key]
	if !ok {
		return &localStringCmd{err: fmt.Errorf("hash not found")}
	}
	value, ok := fields[field]
	if !ok {
		return &localStringCmd{err: fmt.Errorf("field not found")}
	}
	return &localStringCmd{value: value}
}

func (c *localStateStoreClient) HSet(_ context.Context, key string, values ...interface{}) *localStatusCmd {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if _, ok := c.store.hashes[key]; !ok {
		c.store.hashes[key] = make(map[string]string)
	}
	if len(values) == 1 {
		if m, ok := values[0].(map[string]interface{}); ok {
			for field, value := range m {
				c.store.hashes[key][field] = fmt.Sprint(value)
			}
		}
		return &localStatusCmd{}
	}
	for i := 0; i+1 < len(values); i += 2 {
		field := fmt.Sprint(values[i])
		c.store.hashes[key][field] = fmt.Sprint(values[i+1])
	}
	return &localStatusCmd{}
}

func (c *localStateStoreClient) HIncrBy(_ context.Context, key, field string, incr int64) *localIntCmd {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if _, ok := c.store.hashes[key]; !ok {
		c.store.hashes[key] = make(map[string]string)
	}
	current, _ := strconv.ParseInt(c.store.hashes[key][field], 10, 64)
	current += incr
	c.store.hashes[key][field] = strconv.FormatInt(current, 10)
	return &localIntCmd{value: current}
}

func (c *localStateStoreClient) SAdd(_ context.Context, key string, members ...interface{}) *localIntCmd {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if _, ok := c.store.sets[key]; !ok {
		c.store.sets[key] = make(map[string]struct{})
	}
	added := int64(0)
	for _, member := range members {
		value := fmt.Sprint(member)
		if _, ok := c.store.sets[key][value]; !ok {
			c.store.sets[key][value] = struct{}{}
			added++
		}
	}
	return &localIntCmd{value: added}
}

func (c *localStateStoreClient) SRem(_ context.Context, key string, members ...interface{}) *localIntCmd {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	removed := int64(0)
	set := c.store.sets[key]
	for _, member := range members {
		value := fmt.Sprint(member)
		if _, ok := set[value]; ok {
			delete(set, value)
			removed++
		}
	}
	return &localIntCmd{value: removed}
}

func (c *localStateStoreClient) Del(_ context.Context, keys ...string) *localIntCmd {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	removed := int64(0)
	for _, key := range keys {
		if _, ok := c.store.values[key]; ok {
			delete(c.store.values, key)
			removed++
		}
		if _, ok := c.store.hashes[key]; ok {
			delete(c.store.hashes, key)
			removed++
		}
		if _, ok := c.store.sets[key]; ok {
			delete(c.store.sets, key)
			removed++
		}
	}
	return &localIntCmd{value: removed}
}

type localPipeline struct {
	client *localStateStoreClient
}

func (p *localPipeline) HSet(ctx context.Context, key string, values ...interface{}) {
	p.client.HSet(ctx, key, values...)
}

func (p *localPipeline) Set(ctx context.Context, key string, value interface{}, exp time.Duration) {
	p.client.Set(ctx, key, value, exp)
}

func (p *localPipeline) SAdd(ctx context.Context, key string, members ...interface{}) {
	p.client.SAdd(ctx, key, members...)
}

func (p *localPipeline) Exec(_ context.Context) ([]interface{}, error) {
	return nil, nil
}

type StateStore struct {
	client *localStateStoreClient
}

func NewStateStore(_ StateStoreConfig) (*StateStore, error) {
	store := newLocalStore()
	return &StateStore{client: &localStateStoreClient{store: store}}, nil
}

func (r *StateStore) Pipeline() *localPipeline {
	return &localPipeline{client: r.client}
}

func (r *StateStore) HSet(ctx context.Context, key string, values ...interface{}) error {
	return r.client.HSet(ctx, key, values...).Err()
}

func (r *StateStore) HIncrBy(ctx context.Context, key, field string, incr int64) error {
	_, err := r.client.HIncrBy(ctx, key, field, incr).Result()
	return err
}

func (r *StateStore) SAdd(ctx context.Context, key string, members ...interface{}) error {
	_, err := r.client.SAdd(ctx, key, members...).Result()
	return err
}

func (r *StateStore) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

func (r *StateStore) SetWithTTL(ctx context.Context, key, value string, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

func (r *StateStore) SRem(ctx context.Context, key string, members ...interface{}) error {
	_, err := r.client.SRem(ctx, key, members...).Result()
	return err
}

func (r *StateStore) Del(ctx context.Context, keys ...string) error {
	_, err := r.client.Del(ctx, keys...).Result()
	return err
}

func (r *StateStore) Close() error {
	return nil
}

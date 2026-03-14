package core

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisConfig holds Redis connection settings
type RedisConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Database int    `json:"database"`
	PoolSize int    `json:"pool_size"`
}

// RedisClient wraps go-redis with a connection pool
type RedisClient struct {
	client *redis.Client
}

// NewRedisClient creates a new Redis client with connection pooling
func NewRedisClient(cfg RedisConfig) (*RedisClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.Database,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: 2,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	return &RedisClient{client: client}, nil
}

// Pipeline returns a new Redis pipeline for batch operations
func (r *RedisClient) Pipeline() redis.Pipeliner {
	return r.client.Pipeline()
}

// HSet sets hash fields
func (r *RedisClient) HSet(ctx context.Context, key string, values ...interface{}) error {
	return r.client.HSet(ctx, key, values...).Err()
}

// HIncrBy increments a hash field by delta
func (r *RedisClient) HIncrBy(ctx context.Context, key, field string, incr int64) error {
	return r.client.HIncrBy(ctx, key, field, incr).Err()
}

// SAdd adds members to a set
func (r *RedisClient) SAdd(ctx context.Context, key string, members ...interface{}) error {
	return r.client.SAdd(ctx, key, members...).Err()
}

// Get retrieves a string value
func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

// SetWithTTL sets a string value with an expiration time
func (r *RedisClient) SetWithTTL(ctx context.Context, key, value string, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

// SRem removes members from a set
func (r *RedisClient) SRem(ctx context.Context, key string, members ...interface{}) error {
	return r.client.SRem(ctx, key, members...).Err()
}

// Del deletes one or more keys
func (r *RedisClient) Del(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}

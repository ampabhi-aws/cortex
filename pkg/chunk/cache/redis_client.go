package cache

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"

	"github.com/cortexproject/cortex/pkg/util/flagext"
	cortex_tls "github.com/cortexproject/cortex/pkg/util/tls"
)

// RedisConfig defines how a RedisCache should be constructed.
type RedisConfig struct {
	Endpoint    string                  `yaml:"endpoint"`
	MasterName  string                  `yaml:"master_name"`
	Timeout     time.Duration           `yaml:"timeout"`
	Expiration  time.Duration           `yaml:"expiration"`
	DB          int                     `yaml:"db"`
	PoolSize    int                     `yaml:"pool_size"`
	Password    flagext.Secret          `yaml:"password"`
	EnableTLS   bool                    `yaml:"tls_enabled"`
	TLS         cortex_tls.ClientConfig `yaml:",inline"`
	IdleTimeout time.Duration           `yaml:"idle_timeout"`
	MaxConnAge  time.Duration           `yaml:"max_connection_age"`
}

// RegisterFlagsWithPrefix adds the flags required to config this to the given FlagSet
func (cfg *RedisConfig) RegisterFlagsWithPrefix(prefix, description string, f *flag.FlagSet) {
	f.StringVar(&cfg.Endpoint, prefix+"redis.endpoint", "", description+"Redis Server endpoint to use for caching. A comma-separated list of endpoints for Redis Cluster or Redis Sentinel. If empty, no redis will be used.")
	f.StringVar(&cfg.MasterName, prefix+"redis.master-name", "", description+"Redis Sentinel master name. An empty string for Redis Server or Redis Cluster.")
	f.DurationVar(&cfg.Timeout, prefix+"redis.timeout", 500*time.Millisecond, description+"Maximum time to wait before giving up on redis requests.")
	f.DurationVar(&cfg.Expiration, prefix+"redis.expiration", 0, description+"How long keys stay in the redis.")
	f.IntVar(&cfg.DB, prefix+"redis.db", 0, description+"Database index.")
	f.IntVar(&cfg.PoolSize, prefix+"redis.pool-size", 0, description+"Maximum number of connections in the pool.")
	f.Var(&cfg.Password, prefix+"redis.password", description+"Password to use when connecting to redis.")
	f.BoolVar(&cfg.EnableTLS, prefix+"redis.tls-enabled", false, description+"Enable connecting to redis with TLS.")
	// Register the shared TLS client flags (tls_ca_path, tls_cert_path, tls_key_path,
	// tls_server_name, tls_insecure_skip_verify) under the "<prefix>redis" namespace so
	// operators can configure a custom CA, client certificate, and the expected server
	// name for the redis cache connection, matching every other Cortex client.
	// NOTE: tls_insecure_skip_verify disables both chain and hostname verification and
	// is intended for testing only; production deployments should instead configure
	// tls_ca_path (and optionally tls_server_name) to pin the redis server.
	cfg.TLS.RegisterFlagsWithPrefix(prefix+"redis", f)
	f.DurationVar(&cfg.IdleTimeout, prefix+"redis.idle-timeout", 0, description+"Close connections after remaining idle for this duration. If the value is zero, then idle connections are not closed.")
	f.DurationVar(&cfg.MaxConnAge, prefix+"redis.max-connection-age", 0, description+"Close connections older than this duration. If the value is zero, then the pool does not close connections based on age.")
}

type RedisClient struct {
	expiration time.Duration
	timeout    time.Duration
	rdb        redis.UniversalClient
}

// NewRedisClient creates a Redis client. When TLS is enabled, the returned client
// uses a tls.Config built from the shared pkg/util/tls.ClientConfig (CAPath, CertPath,
// KeyPath, ServerName, InsecureSkipVerify) with an explicit MinVersion of TLS 1.2.
func NewRedisClient(cfg *RedisConfig) (*RedisClient, error) {
	opt := &redis.UniversalOptions{
		Addrs:       strings.Split(cfg.Endpoint, ","),
		MasterName:  cfg.MasterName,
		Password:    cfg.Password.Value,
		DB:          cfg.DB,
		PoolSize:    cfg.PoolSize,
		IdleTimeout: cfg.IdleTimeout,
		MaxConnAge:  cfg.MaxConnAge,
	}
	if cfg.EnableTLS {
		tlsConfig, err := cfg.TLS.GetTLSConfig()
		if err != nil {
			return nil, errors.Wrap(err, "failed to build TLS config for redis client")
		}
		// Pin a minimum TLS version to protect against downgrade to legacy protocols.
		tlsConfig.MinVersion = tls.VersionTLS12
		opt.TLSConfig = tlsConfig
	}
	return &RedisClient{
		expiration: cfg.Expiration,
		timeout:    cfg.Timeout,
		rdb:        redis.NewUniversalClient(opt),
	}, nil
}

func (c *RedisClient) Ping(ctx context.Context) error {
	var cancel context.CancelFunc
	if c.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	pong, err := c.rdb.Ping(ctx).Result()
	if err != nil {
		return err
	}
	if pong != "PONG" {
		return fmt.Errorf("redis: Unexpected PING response %q", pong)
	}
	return nil
}

func (c *RedisClient) MSet(ctx context.Context, keys []string, values [][]byte) error {
	var cancel context.CancelFunc
	if c.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	if len(keys) != len(values) {
		return fmt.Errorf("MSet the length of keys and values not equal, len(keys)=%d, len(values)=%d", len(keys), len(values))
	}

	pipe := c.rdb.TxPipeline()
	for i := range keys {
		pipe.Set(ctx, keys[i], values[i], c.expiration)
	}
	_, err := pipe.Exec(ctx)
	return err
}

func (c *RedisClient) MGet(ctx context.Context, keys []string) ([][]byte, error) {
	var cancel context.CancelFunc
	if c.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	ret := make([][]byte, len(keys))

	// redis.UniversalClient can take redis.Client and redis.ClusterClient.
	// if redis.Client is set, then Single node or sentinel configuration. mget is always supported.
	// if redis.ClusterClient is set, then Redis Cluster configuration. mget may not be supported.
	_, isCluster := c.rdb.(*redis.ClusterClient)

	if isCluster {
		for i, key := range keys {
			cmd := c.rdb.Get(ctx, key)
			err := cmd.Err()
			if err == redis.Nil {
				// if key not found, response nil
				continue
			} else if err != nil {
				return nil, err
			}
			ret[i] = StringToBytes(cmd.Val())
		}
	} else {
		cmd := c.rdb.MGet(ctx, keys...)
		if err := cmd.Err(); err != nil {
			return nil, err
		}

		for i, val := range cmd.Val() {
			if val != nil {
				ret[i] = StringToBytes(val.(string))
			}
		}
	}

	return ret, nil
}

func (c *RedisClient) Close() error {
	return c.rdb.Close()
}

// StringToBytes converts string to byte slice. (copied from vendor/github.com/go-redis/redis/v8/internal/util/unsafe.go)
func StringToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			Cap int
		}{s, len(s)},
	))
}

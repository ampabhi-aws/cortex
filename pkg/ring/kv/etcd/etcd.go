package etcd

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/cortexproject/cortex/pkg/ring/kv/codec"
	"github.com/cortexproject/cortex/pkg/util/backoff"
	"github.com/cortexproject/cortex/pkg/util/flagext"
	cortextls "github.com/cortexproject/cortex/pkg/util/tls"
)

// ErrEtcdPasswordWithoutTLS is returned when etcd password authentication is
// configured but TLS is not enabled and no https:// endpoint is configured,
// which would send the credentials over an unencrypted connection.
var ErrEtcdPasswordWithoutTLS = errors.New("etcd password is configured but TLS is not enabled; set -<prefix>etcd.tls-enabled=true (or use an https:// endpoint, or a tls_ca_path/tls_cert_path/tls_key_path) whenever -<prefix>etcd.password is used, otherwise the password would be sent in cleartext")

// Config for a new etcd.Client.
type Config struct {
	Endpoints   []string               `yaml:"endpoints"`
	DialTimeout time.Duration          `yaml:"dial_timeout"`
	MaxRetries  int                    `yaml:"max_retries"`
	EnableTLS   bool                   `yaml:"tls_enabled"`
	TLS         cortextls.ClientConfig `yaml:",inline"`

	UserName string `yaml:"username"`
	Password string `yaml:"password"`
}

// Clientv3Facade is a subset of all Etcd client operations that are required
// to implement an Etcd version of kv.Client
type Clientv3Facade interface {
	clientv3.KV
	clientv3.Watcher
}

// Client implements kv.Client for etcd.
type Client struct {
	cfg    Config
	codec  codec.Codec
	cli    Clientv3Facade
	logger log.Logger
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	cfg.RegisterFlagsWithPrefix(f, "")
}

// RegisterFlagsWithPrefix adds the flags required to config this to the given FlagSet.
func (cfg *Config) RegisterFlagsWithPrefix(f *flag.FlagSet, prefix string) {
	cfg.Endpoints = []string{}
	f.Var((*flagext.StringSlice)(&cfg.Endpoints), prefix+"etcd.endpoints", "The etcd endpoints to connect to.")
	f.DurationVar(&cfg.DialTimeout, prefix+"etcd.dial-timeout", 10*time.Second, "The dial timeout for the etcd connection.")
	f.IntVar(&cfg.MaxRetries, prefix+"etcd.max-retries", 10, "The maximum number of retries to do for failed ops.")
	f.BoolVar(&cfg.EnableTLS, prefix+"etcd.tls-enabled", false, "Enable TLS.")
	f.StringVar(&cfg.UserName, prefix+"etcd.username", "", "Etcd username.")
	f.StringVar(&cfg.Password, prefix+"etcd.password", "", "Etcd password. Setting this requires TLS to be enabled (via -<prefix>etcd.tls-enabled=true, an https:// endpoint, or TLS file paths) so the password is not sent in cleartext; prefer certificate-based client authentication (tls_cert_path/tls_key_path).")
	cfg.TLS.RegisterFlagsWithPrefix(prefix+"etcd", f)
}

// hasHTTPSEndpoint reports whether any configured endpoint uses the https://
// (or unixs://) scheme, in which case the vendored etcd client requires TLS.
func (cfg *Config) hasHTTPSEndpoint() bool {
	for _, ep := range cfg.Endpoints {
		if strings.HasPrefix(ep, "https://") || strings.HasPrefix(ep, "unixs://") {
			return true
		}
	}
	return false
}

// hasTLSPaths reports whether the operator has configured any TLS file path or
// server-name override, which strongly implies TLS was intended.
func (cfg *Config) hasTLSPaths() bool {
	return cfg.TLS.CAPath != "" || cfg.TLS.CertPath != "" || cfg.TLS.KeyPath != "" || cfg.TLS.ServerName != ""
}

// shouldUseTLS returns true when TLS is explicitly enabled, or when the
// configuration implies TLS (https:// endpoint, or any TLS file path /
// server-name override). This prevents operator-supplied TLS material from
// being silently discarded because the separate -<prefix>etcd.tls-enabled flag
// was left at its default.
func (cfg *Config) shouldUseTLS() bool {
	return cfg.EnableTLS || cfg.hasHTTPSEndpoint() || cfg.hasTLSPaths()
}

// Validate verifies that the etcd configuration is self-consistent. In
// particular it refuses to send password credentials over an unencrypted
// connection: using -<prefix>etcd.password requires -<prefix>etcd.tls-enabled=true
// (or an https:// endpoint, or TLS file paths that imply TLS). Prefer
// certificate-based client authentication (tls_cert_path/tls_key_path) over
// the username/password mechanism.
func (cfg *Config) Validate() error {
	if cfg.Password != "" && !cfg.shouldUseTLS() {
		return ErrEtcdPasswordWithoutTLS
	}
	return nil
}

// GetTLS sets the TLS config field with certs. TLS is used whenever the
// operator explicitly enabled it, configured an https:// (or unixs://)
// endpoint, or supplied any TLS file path / server-name override; otherwise a
// nil *tls.Config is returned and the etcd client dials in plaintext.
func (cfg *Config) GetTLS() (*tls.Config, error) {
	if !cfg.shouldUseTLS() {
		return nil, nil
	}
	tlsInfo := &transport.TLSInfo{
		CertFile:           cfg.TLS.CertPath,
		KeyFile:            cfg.TLS.KeyPath,
		TrustedCAFile:      cfg.TLS.CAPath,
		ServerName:         cfg.TLS.ServerName,
		InsecureSkipVerify: cfg.TLS.InsecureSkipVerify,
	}
	return tlsInfo.ClientConfig()
}

// New makes a new Client.
func New(cfg Config, codec codec.Codec, logger log.Logger) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid etcd config")
	}
	tlsConfig, err := cfg.GetTLS()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to initialise TLS configuration for etcd")
	}
	if cfg.Password != "" && cfg.TLS.CertPath != "" && cfg.TLS.KeyPath != "" {
		level.Warn(logger).Log("msg", "etcd client is configured with both password and client certificate authentication; prefer certificate-based client auth over username/password")
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: cfg.DialTimeout,
		// Configure the keepalive to make sure that the client reconnects
		// to the etcd service endpoint(s) in case the current connection is
		// dead (ie. the node where etcd is running is dead or a network
		// partition occurs).
		//
		// The settings:
		// - DialKeepAliveTime: time before the client pings the server to
		//   see if transport is alive (10s hardcoded)
		// - DialKeepAliveTimeout: time the client waits for a response for
		//   the keep-alive probe (set to 2x dial timeout, in order to avoid
		//   exposing another config option which is likely to be a factor of
		//   the dial timeout anyway)
		// - PermitWithoutStream: whether the client should send keepalive pings
		//   to server without any active streams (enabled)
		DialKeepAliveTime:    10 * time.Second,
		DialKeepAliveTimeout: 2 * cfg.DialTimeout,
		PermitWithoutStream:  true,
		TLS:                  tlsConfig,
		Username:             cfg.UserName,
		Password:             cfg.Password,
	})
	if err != nil {
		return nil, err
	}

	return &Client{
		cfg:    cfg,
		codec:  codec,
		cli:    cli,
		logger: logger,
	}, nil
}

// CAS implements kv.Client.
func (c *Client) CAS(ctx context.Context, key string, f func(in interface{}) (out interface{}, retry bool, err error)) error {
	var revision int64
	var lastErr error

	for i := 0; i < c.cfg.MaxRetries; i++ {
		resp, err := c.cli.Get(ctx, key)
		if err != nil {
			level.Error(c.logger).Log("msg", "error getting key", "key", key, "err", err)
			lastErr = err
			continue
		}

		var intermediate interface{}
		if len(resp.Kvs) > 0 {
			intermediate, err = c.codec.Decode(resp.Kvs[0].Value)
			if err != nil {
				level.Error(c.logger).Log("msg", "error decoding key", "key", key, "err", err)
				lastErr = err
				continue
			}
			revision = resp.Kvs[0].Version
		}

		var retry bool
		intermediate, retry, err = f(intermediate)
		if err != nil {
			if !retry {
				return err
			}
			lastErr = err
			continue
		}

		// Callback returning nil means it doesn't want to CAS anymore.
		if intermediate == nil {
			return nil
		}

		buf, err := c.codec.Encode(intermediate)
		if err != nil {
			level.Error(c.logger).Log("msg", "error serialising value", "key", key, "err", err)
			lastErr = err
			continue
		}

		result, err := c.cli.Txn(ctx).
			If(clientv3.Compare(clientv3.Version(key), "=", revision)).
			Then(clientv3.OpPut(key, string(buf))).
			Commit()
		if err != nil {
			level.Error(c.logger).Log("msg", "error CASing", "key", key, "err", err)
			lastErr = err
			continue
		}
		// result is not Succeeded if the the comparison was false, meaning if the modify indexes did not match.
		if !result.Succeeded {
			level.Debug(c.logger).Log("msg", "failed to CAS, revision and version did not match in etcd", "key", key, "revision", revision)
			continue
		}

		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("failed to CAS %s", key)
}

// WatchKey implements kv.Client.
func (c *Client) WatchKey(ctx context.Context, key string, f func(interface{}) bool) {
	backoff := backoff.New(ctx, backoff.Config{
		MinBackoff: 1 * time.Second,
		MaxBackoff: 1 * time.Minute,
	})

	// Ensure the context used by the Watch is always cancelled.
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

outer:
	for backoff.Ongoing() {
		for resp := range c.cli.Watch(watchCtx, key) {
			if err := resp.Err(); err != nil {
				level.Error(c.logger).Log("msg", "watch error", "key", key, "err", err)
				continue outer
			}

			backoff.Reset()

			for _, event := range resp.Events {
				out, err := c.codec.Decode(event.Kv.Value)
				if err != nil {
					level.Error(c.logger).Log("msg", "error decoding key", "key", key, "err", err)
					continue
				}

				if !f(out) {
					return
				}
			}
		}
	}
}

// WatchPrefix implements kv.Client.
func (c *Client) WatchPrefix(ctx context.Context, key string, f func(string, interface{}) bool) {
	backoff := backoff.New(ctx, backoff.Config{
		MinBackoff: 1 * time.Second,
		MaxBackoff: 1 * time.Minute,
	})

	// Ensure the context used by the Watch is always cancelled.
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

outer:
	for backoff.Ongoing() {
		for resp := range c.cli.Watch(watchCtx, key, clientv3.WithPrefix()) {
			if err := resp.Err(); err != nil {
				level.Error(c.logger).Log("msg", "watch error", "key", key, "err", err)
				continue outer
			}

			backoff.Reset()

			for _, event := range resp.Events {
				if event.Kv.Version == 0 && event.Kv.Value == nil {
					// Delete notification. Since not all KV store clients (and codecs) support this, we ignore it.
					continue
				}

				out, err := c.codec.Decode(event.Kv.Value)
				if err != nil {
					level.Error(c.logger).Log("msg", "error decoding key", "key", key, "err", err)
					continue
				}

				if !f(string(event.Kv.Key), out) {
					return
				}
			}
		}
	}
}

// List implements kv.Client.
func (c *Client) List(ctx context.Context, prefix string) ([]string, error) {
	resp, err := c.cli.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		keys = append(keys, string(kv.Key))
	}
	return keys, nil
}

// Get implements kv.Client.
func (c *Client) Get(ctx context.Context, key string) (interface{}, error) {
	resp, err := c.cli.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, nil
	} else if len(resp.Kvs) != 1 {
		return nil, fmt.Errorf("got %d kvs, expected 1 or 0", len(resp.Kvs))
	}
	return c.codec.Decode(resp.Kvs[0].Value)
}

// Delete implements kv.Client.
func (c *Client) Delete(ctx context.Context, key string) error {
	_, err := c.cli.Delete(ctx, key)
	return err
}

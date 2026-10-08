package grpcclient

import (
	"flag"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"

	"github.com/cortexproject/cortex/pkg/util/backoff"
	"github.com/cortexproject/cortex/pkg/util/grpcencoding/snappy"
	"github.com/cortexproject/cortex/pkg/util/tls"
)

// clientTLSEnabledGauge exposes whether TLS is enabled for each gRPC client.
// Operators can alert on unexpectedly plaintext inter-component links.
var clientTLSEnabledGauge = promauto.With(prometheus.DefaultRegisterer).NewGaugeVec(prometheus.GaugeOpts{
	Name: "cortex_client_tls_enabled",
	Help: "Whether TLS is enabled for a Cortex gRPC client, labelled by the client's flag prefix. 1 if enabled, 0 otherwise.",
}, []string{"client"})

// Config for a gRPC client.
type Config struct {
	MaxRecvMsgSize  int     `yaml:"max_recv_msg_size"`
	MaxSendMsgSize  int     `yaml:"max_send_msg_size"`
	GRPCCompression string  `yaml:"grpc_compression"`
	RateLimit       float64 `yaml:"rate_limit"`
	RateLimitBurst  int     `yaml:"rate_limit_burst"`

	BackoffOnRatelimits bool           `yaml:"backoff_on_ratelimits"`
	BackoffConfig       backoff.Config `yaml:"backoff_config"`

	TLSEnabled bool             `yaml:"tls_enabled"`
	TLS        tls.ClientConfig `yaml:",inline"`

	// prefix is the flag prefix used when this Config was registered. It is
	// used purely for diagnostics (log context, metric labels) and has no
	// effect on behaviour. Unexported so it is never marshaled.
	prefix string
}

// RegisterFlags registers flags.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	cfg.RegisterFlagsWithPrefix("", f)
}

// RegisterFlagsWithPrefix registers flags with prefix.
func (cfg *Config) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	cfg.prefix = prefix
	f.IntVar(&cfg.MaxRecvMsgSize, prefix+".grpc-max-recv-msg-size", 100<<20, "gRPC client max receive message size (bytes).")
	f.IntVar(&cfg.MaxSendMsgSize, prefix+".grpc-max-send-msg-size", 16<<20, "gRPC client max send message size (bytes).")
	f.StringVar(&cfg.GRPCCompression, prefix+".grpc-compression", "", "Use compression when sending messages. Supported values are: 'gzip', 'snappy' and '' (disable compression)")
	f.Float64Var(&cfg.RateLimit, prefix+".grpc-client-rate-limit", 0., "Rate limit for gRPC client; 0 means disabled.")
	f.IntVar(&cfg.RateLimitBurst, prefix+".grpc-client-rate-limit-burst", 0, "Rate limit burst for gRPC client.")
	f.BoolVar(&cfg.BackoffOnRatelimits, prefix+".backoff-on-ratelimits", false, "Enable backoff and retry when we hit ratelimits.")
	f.BoolVar(&cfg.TLSEnabled, prefix+".tls-enabled", cfg.TLSEnabled, "Enable TLS in the GRPC client. This flag needs to be enabled when any other TLS flag is set. If set to false, insecure connection to gRPC server will be used.")

	cfg.BackoffConfig.RegisterFlagsWithPrefix(prefix, f)

	cfg.TLS.RegisterFlagsWithPrefix(prefix, f)
}

func (cfg *Config) Validate(log log.Logger) error {
	switch cfg.GRPCCompression {
	case gzip.Name, snappy.Name, "":
		// valid
	default:
		return errors.Errorf("unsupported compression type: %s", cfg.GRPCCompression)
	}

	// Fail closed when TLS material has been configured but TLS is not
	// enabled: silently falling back to plaintext would be an invisible
	// downgrade of inter-component security.
	if err := cfg.TLS.Validate(cfg.TLSEnabled); err != nil {
		return errors.Wrapf(err, "invalid TLS config for gRPC client %q", cfg.prefix)
	}

	// Record the effective TLS state so operators can alert on unexpectedly
	// plaintext inter-component links. Also emit a warning when a client is
	// configured without TLS so the condition is not completely invisible.
	clientLabel := cfg.prefix
	if clientLabel == "" {
		clientLabel = "unknown"
	}
	if cfg.TLSEnabled {
		clientTLSEnabledGauge.WithLabelValues(clientLabel).Set(1)
	} else {
		clientTLSEnabledGauge.WithLabelValues(clientLabel).Set(0)
		if log != nil {
			level.Warn(log).Log("msg", "gRPC client configured without TLS; inter-component traffic will be plaintext", "client", clientLabel)
		}
	}

	return nil
}

// CallOptions returns the config in terms of CallOptions.
func (cfg *Config) CallOptions() []grpc.CallOption {
	var opts []grpc.CallOption
	opts = append(opts, grpc.MaxCallRecvMsgSize(cfg.MaxRecvMsgSize))
	opts = append(opts, grpc.MaxCallSendMsgSize(cfg.MaxSendMsgSize))
	if cfg.GRPCCompression != "" {
		opts = append(opts, grpc.UseCompressor(cfg.GRPCCompression))
	}
	return opts
}

// DialOption returns the config as a grpc.DialOptions.
func (cfg *Config) DialOption(unaryClientInterceptors []grpc.UnaryClientInterceptor, streamClientInterceptors []grpc.StreamClientInterceptor) ([]grpc.DialOption, error) {
	var opts []grpc.DialOption
	tlsOpts, err := cfg.TLS.GetGRPCDialOptions(cfg.TLSEnabled)
	if err != nil {
		return nil, err
	}
	opts = append(opts, tlsOpts...)

	if cfg.BackoffOnRatelimits {
		unaryClientInterceptors = append([]grpc.UnaryClientInterceptor{NewBackoffRetry(cfg.BackoffConfig)}, unaryClientInterceptors...)
	}

	if cfg.RateLimit > 0 {
		unaryClientInterceptors = append([]grpc.UnaryClientInterceptor{NewRateLimiter(cfg)}, unaryClientInterceptors...)
	}

	return append(
		opts,
		grpc.WithDefaultCallOptions(cfg.CallOptions()...),
		grpc.WithUnaryInterceptor(middleware.ChainUnaryClient(unaryClientInterceptors...)),
		grpc.WithStreamInterceptor(middleware.ChainStreamClient(streamClientInterceptors...)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Second * 20,
			Timeout:             time.Second * 10,
			PermitWithoutStream: true,
		}),
	), nil
}

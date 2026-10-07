package alertmanager

import (
	"flag"
	"time"

	"github.com/go-kit/log"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/cortexproject/cortex/pkg/alertmanager/alertmanagerpb"
	"github.com/cortexproject/cortex/pkg/ring/client"
	"github.com/cortexproject/cortex/pkg/util/grpcclient"
	"github.com/cortexproject/cortex/pkg/util/tls"
)

// ClientsPool is the interface used to get the client from the pool for a specified address.
type ClientsPool interface {
	// GetClientFor returns the alertmanager client for the given address.
	GetClientFor(addr string) (Client, error)
}

// Client is the interface that should be implemented by any client used to read/write data to an alertmanager via GRPC.
type Client interface {
	alertmanagerpb.AlertmanagerClient

	// RemoteAddress returns the address of the remote alertmanager and is used to uniquely
	// identify an alertmanager instance.
	RemoteAddress() string
}

// ClientConfig is the configuration struct for the alertmanager client.
type ClientConfig struct {
	RemoteTimeout         time.Duration    `yaml:"remote_timeout"`
	TLSEnabled            bool             `yaml:"tls_enabled"`
	TLS                   tls.ClientConfig `yaml:",inline"`
	MaxConcurrentRequests int              `yaml:"max_concurrent_requests"`
	MaxMergeBodiesBytes   int64            `yaml:"max_merge_bodies_bytes"`
}

// RegisterFlagsWithPrefix registers flags with prefix.
func (cfg *ClientConfig) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.BoolVar(&cfg.TLSEnabled, prefix+".tls-enabled", cfg.TLSEnabled, "Enable TLS in the GRPC client. This flag needs to be enabled when any other TLS flag is set. If set to false, insecure connection to gRPC server will be used.")
	f.DurationVar(&cfg.RemoteTimeout, prefix+".remote-timeout", 2*time.Second, "Timeout for downstream alertmanagers.")
	f.IntVar(&cfg.MaxConcurrentRequests, prefix+".max-concurrent-requests", 100, "Maximum number of concurrent in-flight distributor requests to the alertmanagers. 0 to disable the limit.")
	f.Int64Var(&cfg.MaxMergeBodiesBytes, prefix+".max-merge-bodies-bytes", 64<<20, "Maximum aggregate size (bytes) of per-peer response bodies kept in memory before merging quorum reads. Requests exceeding this limit are failed before more memory is allocated. 0 to disable the limit.")
	cfg.TLS.RegisterFlagsWithPrefix(prefix, f)
}

type alertmanagerClientsPool struct {
	pool *client.Pool
}

// newAlertmanagerClientsPoolWithMaxMsgSize builds the inter-alertmanager gRPC client
// pool. The caller configures the gRPC Max{Recv,Send}MsgSize so that it stays consistent
// with the HTTP body limit advertised by -alertmanager.max-recv-msg-size. This avoids the
// previous hard-coded 4 MB send cap that silently failed 4-16 MB writes after they had
// already been buffered and fanned out.
func newAlertmanagerClientsPoolWithMaxMsgSize(discovery client.PoolServiceDiscovery, amClientCfg ClientConfig, maxMsgSize int, logger log.Logger, reg prometheus.Registerer) ClientsPool {
	if maxMsgSize <= 0 {
		maxMsgSize = 16 * 1024 * 1024
	}
	// We prefer sane defaults instead of exposing further config options.
	grpcCfg := grpcclient.Config{
		MaxRecvMsgSize:      maxMsgSize,
		MaxSendMsgSize:      maxMsgSize,
		GRPCCompression:     "",
		RateLimit:           0,
		RateLimitBurst:      0,
		BackoffOnRatelimits: false,
		TLSEnabled:          amClientCfg.TLSEnabled,
		TLS:                 amClientCfg.TLS,
	}

	requestDuration := promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
		Name:    "cortex_alertmanager_distributor_client_request_duration_seconds",
		Help:    "Time spent executing requests from an alertmanager to another alertmanager.",
		Buckets: prometheus.ExponentialBuckets(0.008, 4, 7),
	}, []string{"operation", "status_code"})

	factory := func(addr string) (client.PoolClient, error) {
		return dialAlertmanagerClient(grpcCfg, addr, requestDuration)
	}

	poolCfg := client.PoolConfig{
		CheckInterval:      time.Minute,
		HealthCheckEnabled: true,
		HealthCheckTimeout: 10 * time.Second,
	}

	clientsCount := promauto.With(reg).NewGauge(prometheus.GaugeOpts{
		Namespace: "cortex",
		Name:      "alertmanager_distributor_clients",
		Help:      "The current number of alertmanager distributor clients in the pool.",
	})

	return &alertmanagerClientsPool{pool: client.NewPool("alertmanager", poolCfg, discovery, factory, clientsCount, logger)}
}

func (f *alertmanagerClientsPool) GetClientFor(addr string) (Client, error) {
	c, err := f.pool.GetClientFor(addr)
	if err != nil {
		return nil, err
	}
	return c.(Client), nil
}

func dialAlertmanagerClient(cfg grpcclient.Config, addr string, requestDuration *prometheus.HistogramVec) (*alertmanagerClient, error) {
	opts, err := cfg.DialOption(grpcclient.Instrument(requestDuration))
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to dial alertmanager %s", addr)
	}

	return &alertmanagerClient{
		AlertmanagerClient: alertmanagerpb.NewAlertmanagerClient(conn),
		HealthClient:       grpc_health_v1.NewHealthClient(conn),
		conn:               conn,
	}, nil
}

type alertmanagerClient struct {
	alertmanagerpb.AlertmanagerClient
	grpc_health_v1.HealthClient
	conn *grpc.ClientConn
}

func (c *alertmanagerClient) Close() error {
	return c.conn.Close()
}

func (c *alertmanagerClient) String() string {
	return c.RemoteAddress()
}

func (c *alertmanagerClient) RemoteAddress() string {
	return c.conn.Target()
}

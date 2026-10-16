package v2

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/weaveworks/common/httpgrpc"

	"github.com/cortexproject/cortex/pkg/frontend/v2/frontendv2pb"
	"github.com/cortexproject/cortex/pkg/querier/stats"
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util/flagext"
	"github.com/cortexproject/cortex/pkg/util/grpcclient"
	"github.com/cortexproject/cortex/pkg/util/httpgrpcutil"
	"github.com/cortexproject/cortex/pkg/util/services"
)

// Config for a Frontend.
type Config struct {
	SchedulerAddress  string            `yaml:"scheduler_address"`
	DNSLookupPeriod   time.Duration     `yaml:"scheduler_dns_lookup_period"`
	WorkerConcurrency int               `yaml:"scheduler_worker_concurrency"`
	GRPCClientConfig  grpcclient.Config `yaml:"grpc_client_config"`

	// Used to find local IP address, that is sent to scheduler and querier-worker.
	InfNames []string `yaml:"instance_interface_names"`

	// If set, address is not computed from interfaces.
	Addr string `yaml:"address" doc:"hidden"`
	Port int    `doc:"hidden"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.StringVar(&cfg.SchedulerAddress, "frontend.scheduler-address", "", "DNS hostname used for finding query-schedulers.")
	f.DurationVar(&cfg.DNSLookupPeriod, "frontend.scheduler-dns-lookup-period", 10*time.Second, "How often to resolve the scheduler-address, in order to look for new query-scheduler instances.")
	f.IntVar(&cfg.WorkerConcurrency, "frontend.scheduler-worker-concurrency", 5, "Number of concurrent workers forwarding queries to single query-scheduler.")

	cfg.InfNames = []string{"eth0", "en0"}
	f.Var((*flagext.StringSlice)(&cfg.InfNames), "frontend.instance-interface-names", "Name of network interface to read address from. This address is sent to query-scheduler and querier, which uses it to send the query response back to query-frontend.")
	f.StringVar(&cfg.Addr, "frontend.instance-addr", "", "IP address to advertise to querier (via scheduler) (resolved via interfaces by default).")
	f.IntVar(&cfg.Port, "frontend.instance-port", 0, "Port to advertise to querier (via scheduler) (defaults to server.grpc-listen-port).")

	cfg.GRPCClientConfig.RegisterFlagsWithPrefix("frontend.grpc-client-config", f)
}

// Frontend implements GrpcRoundTripper. It queues HTTP requests,
// dispatches them to backends via gRPC, and handles retries for requests which failed.
type Frontend struct {
	services.Service

	cfg Config
	log log.Logger

	// frontend workers will read from this channel, and send request to scheduler.
	requestsCh chan *frontendRequest

	schedulerWorkers *frontendSchedulerWorkers
	requests         *requestsInProgress
}

type frontendRequest struct {
	queryID      uint64
	request      *httpgrpc.HTTPRequest
	userID       string
	statsEnabled bool

	cancel context.CancelFunc

	enqueue  chan enqueueResult
	response chan *frontendv2pb.QueryResultRequest
}

type enqueueStatus int

const (
	// Sent to scheduler successfully, and frontend should wait for response now.
	waitForResponse enqueueStatus = iota

	// Failed to forward request to scheduler, frontend will try again.
	failed
)

type enqueueResult struct {
	status enqueueStatus

	cancelCh chan<- uint64 // Channel that can be used for request cancellation. If nil, cancellation is not possible.
}

// NewFrontend creates a new frontend.
func NewFrontend(cfg Config, log log.Logger, reg prometheus.Registerer) (*Frontend, error) {
	requestsCh := make(chan *frontendRequest)

	schedulerWorkers, err := newFrontendSchedulerWorkers(cfg, fmt.Sprintf("%s:%d", cfg.Addr, cfg.Port), requestsCh, log)
	if err != nil {
		return nil, err
	}

	f := &Frontend{
		cfg:              cfg,
		log:              log,
		requestsCh:       requestsCh,
		schedulerWorkers: schedulerWorkers,
		requests:         newRequestsInProgress(),
	}

	promauto.With(reg).NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cortex_query_frontend_queries_in_progress",
		Help: "Number of queries in progress handled by this frontend.",
	}, func() float64 {
		return float64(f.requests.count())
	})

	promauto.With(reg).NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cortex_query_frontend_connected_schedulers",
		Help: "Number of schedulers this frontend is connected to.",
	}, func() float64 {
		return float64(f.schedulerWorkers.getWorkersCount())
	})

	f.Service = services.NewIdleService(f.starting, f.stopping)
	return f, nil
}

func (f *Frontend) starting(ctx context.Context) error {
	return errors.Wrap(services.StartAndAwaitRunning(ctx, f.schedulerWorkers), "failed to start frontend scheduler workers")
}

func (f *Frontend) stopping(_ error) error {
	return errors.Wrap(services.StopAndAwaitTerminated(context.Background(), f.schedulerWorkers), "failed to stop frontend scheduler workers")
}

// RoundTripGRPC round trips a proto (instead of a HTTP request).
func (f *Frontend) RoundTripGRPC(ctx context.Context, req *httpgrpc.HTTPRequest) (*httpgrpc.HTTPResponse, error) {
	if s := f.State(); s != services.Running {
		return nil, fmt.Errorf("frontend not running: %v", s)
	}

	tenantIDs, err := tenant.TenantIDs(ctx)
	if err != nil {
		return nil, err
	}
	userID := tenant.JoinTenantIDs(tenantIDs)

	// Propagate trace context in gRPC too - this will be ignored if using HTTP.
	tracer, span := opentracing.GlobalTracer(), opentracing.SpanFromContext(ctx)
	if tracer != nil && span != nil {
		carrier := (*httpgrpcutil.HttpgrpcHeadersCarrier)(req)
		if err := tracer.Inject(span.Context(), opentracing.HTTPHeaders, carrier); err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Generate a cryptographically unpredictable 64-bit identifier for this
	// query. Previously this field was produced by a sequential counter
	// seeded once per process from math/rand, so any party that learned a
	// single in-flight queryID could predict every subsequent one and
	// inject arbitrary HTTP responses into other tenants' queries via
	// FrontendForQuerier.QueryResult. Generating each queryID with
	// crypto/rand makes it an unforgeable per-query token: the scheduler
	// only forwards it to the querier it dispatched this query to, and the
	// responder must present it back to the frontend for the result to be
	// accepted (see QueryResult below).
	queryID, err := newQueryID()
	if err != nil {
		return nil, err
	}

	freq := &frontendRequest{
		queryID:      queryID,
		request:      req,
		userID:       userID,
		statsEnabled: stats.IsEnabled(ctx),

		cancel: cancel,

		// Buffer of 1 to ensure response or error can be written to the channel
		// even if this goroutine goes away due to client context cancellation.
		enqueue:  make(chan enqueueResult, 1),
		response: make(chan *frontendv2pb.QueryResultRequest, 1),
	}

	if !f.requests.putIfAbsent(freq) {
		return nil, fmt.Errorf("query identifier collision; please retry")
	}
	defer f.requests.delete(freq.queryID)

	retries := f.cfg.WorkerConcurrency + 1 // To make sure we hit at least two different schedulers.

enqueueAgain:
	select {
	case <-ctx.Done():
		return nil, ctx.Err()

	case f.requestsCh <- freq:
		// Enqueued, let's wait for response.
	}

	var cancelCh chan<- uint64

	select {
	case <-ctx.Done():
		return nil, ctx.Err()

	case enqRes := <-freq.enqueue:
		if enqRes.status == waitForResponse {
			cancelCh = enqRes.cancelCh
			break // go wait for response.
		} else if enqRes.status == failed {
			retries--
			if retries > 0 {
				goto enqueueAgain
			}
		}

		return nil, httpgrpc.Errorf(http.StatusInternalServerError, "failed to enqueue request")
	}

	select {
	case <-ctx.Done():
		if cancelCh != nil {
			select {
			case cancelCh <- freq.queryID:
				// cancellation sent.
			default:
				// failed to cancel, ignore.
			}
		}
		return nil, ctx.Err()

	case resp := <-freq.response:
		if stats.ShouldTrackHTTPGRPCResponse(resp.HttpResponse) {
			stats := stats.FromContext(ctx)
			stats.Merge(resp.Stats) // Safe if stats is nil.
		}

		return resp.HttpResponse, nil
	}
}

func (f *Frontend) QueryResult(ctx context.Context, qrReq *frontendv2pb.QueryResultRequest) (*frontendv2pb.QueryResultResponse, error) {
	tenantIDs, err := tenant.TenantIDs(ctx)
	if err != nil {
		return nil, err
	}
	userID := tenant.JoinTenantIDs(tenantIDs)

	req := f.requests.get(qrReq.QueryID)
	// Authenticate the responder before accepting its result. The queryID
	// is a 64-bit per-query token produced by crypto/rand (see
	// RoundTripGRPC), and the scheduler hands it out only to the single
	// querier it dispatched this query to. If a request with this exact
	// queryID is in flight on this frontend AND the caller-asserted tenant
	// ID matches the tenant that issued it, we accept the response.
	// Previously the queryID was produced by a predictable sequential
	// counter, so any party that learned one in-flight ID could spoof
	// future responses - this is the vulnerability being fixed.
	if req != nil && req.userID == userID {
		select {
		case req.response <- qrReq:
			// Should always be possible, unless QueryResult is called multiple times with the same queryID.
		default:
			level.Warn(f.log).Log("msg", "failed to write query result to the response channel", "queryID", qrReq.QueryID, "user", userID)
		}
	} else if req != nil {
		// queryID matches an in-flight request but the caller is asserting a
		// different tenant: drop the result (stale response after frontend
		// restart, or an attempt to leak the result cross-tenant).
		level.Warn(f.log).Log("msg", "rejected query result with mismatched tenant", "queryID", qrReq.QueryID, "user", userID)
	}

	return &frontendv2pb.QueryResultResponse{}, nil
}

// newQueryID returns a 64-bit per-query identifier drawn from crypto/rand.
// This value doubles as the authentication token the responding querier
// must present when calling FrontendForQuerier.QueryResult: because the
// scheduler only hands the ID to the querier it dispatched the query to,
// a successful presentation proves the caller is that querier (or acting
// on its behalf). Replacing the previous sequential counter with an
// unpredictable value closes the CWE-290 result-channel spoofing path on
// the querier->frontend channel.
func newQueryID() (uint64, error) {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return 0, errors.Wrap(err, "failed to generate query identifier")
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// CheckReady determines if the query frontend is ready.  Function parameters/return
// chosen to match the same method in the ingester
func (f *Frontend) CheckReady(_ context.Context) error {
	workers := f.schedulerWorkers.getWorkersCount()

	// If frontend is connected to at least one scheduler, we are ready.
	if workers > 0 {
		return nil
	}

	msg := fmt.Sprintf("not ready: number of schedulers this worker is connected to is %d", workers)
	level.Info(f.log).Log("msg", msg)
	return errors.New(msg)
}

type requestsInProgress struct {
	mu       sync.Mutex
	requests map[uint64]*frontendRequest
}

func newRequestsInProgress() *requestsInProgress {
	return &requestsInProgress{
		requests: map[uint64]*frontendRequest{},
	}
}

func (r *requestsInProgress) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.requests)
}

// putIfAbsent inserts req only if no in-flight request currently uses the
// same queryID. It returns false on collision so the caller can retry with a
// freshly generated identifier instead of silently overwriting another
// tenant's pending request. With a 64-bit crypto/rand queryID this is only
// a safety net; the practical collision probability is negligible.
func (r *requestsInProgress) putIfAbsent(req *frontendRequest) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.requests[req.queryID]; exists {
		return false
	}
	r.requests[req.queryID] = req
	return true
}

func (r *requestsInProgress) delete(queryID uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.requests, queryID)
}

func (r *requestsInProgress) get(queryID uint64) *frontendRequest {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.requests[queryID]
}

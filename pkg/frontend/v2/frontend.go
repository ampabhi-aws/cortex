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
	"go.uber.org/atomic"

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

	// delivered is set the first time a result for this request is accepted,
	// so subsequent QueryResult calls for the same queryID (from the real
	// querier delivering late or from a forged peer) are rejected rather
	// than racing to overwrite the already-latched result.
	delivered atomic.Bool
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

	freq := &frontendRequest{
		request:      req,
		userID:       userID,
		statsEnabled: stats.IsEnabled(ctx),

		cancel: cancel,

		// Buffer of 1 to ensure response or error can be written to the channel
		// even if this goroutine goes away due to client context cancellation.
		enqueue:  make(chan enqueueResult, 1),
		response: make(chan *frontendv2pb.QueryResultRequest, 1),
	}

	// Pick an unguessable, unique queryID. The queryID doubles as the
	// capability token that authorises a querier to deliver this query's
	// result via QueryResult: because the previous counter-based scheme was
	// predictable to any peer that observed one in-flight ID, a forged peer
	// could enumerate IDs and inject responses into other queries. Draw the
	// value from crypto/rand instead and reject the (vanishingly rare) case
	// of a collision with another in-flight query.
	queryID, err := f.requests.putWithRandomID(freq)
	if err != nil {
		return nil, err
	}
	freq.queryID = queryID
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
	// Authorisation for result delivery is a conjunction of three checks:
	//
	//   1. The queryID must identify an in-flight request on this frontend.
	//      queryIDs are drawn from crypto/rand (see RoundTripGRPC), so a peer
	//      that has not been dispatched this query cannot guess the ID of a
	//      victim's in-flight query by enumerating a counter.
	//   2. The tenant resolved from the gRPC metadata must match the tenant
	//      of the dispatched request. This defends against stale responses
	//      received after a frontend restart and against a different tenant's
	//      querier being told to deliver to the wrong query.
	//   3. Only the first result for a given queryID is accepted; a second
	//      delivery (whether a legitimate retry or a forgery racing the real
	//      querier) is rejected with a warning instead of silently
	//      overwriting the already-latched response via the buffered channel.
	if req == nil || req.userID != userID {
		level.Warn(f.log).Log("msg", "rejecting QueryResult: unknown queryID or tenant mismatch", "queryID", qrReq.QueryID, "user", userID)
		return &frontendv2pb.QueryResultResponse{}, nil
	}
	if !req.delivered.CAS(false, true) {
		level.Warn(f.log).Log("msg", "rejecting duplicate QueryResult for already-delivered query", "queryID", qrReq.QueryID, "user", userID)
		return &frontendv2pb.QueryResultResponse{}, nil
	}
	select {
	case req.response <- qrReq:
		// First (and only) accepted delivery for this queryID.
	default:
		// The response channel is buffered to 1 and we just claimed the
		// single delivery slot via `delivered`, so this branch is
		// unreachable in practice.
		level.Warn(f.log).Log("msg", "failed to write query result to the response channel", "queryID", qrReq.QueryID, "user", userID)
	}

	return &frontendv2pb.QueryResultResponse{}, nil
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

func (r *requestsInProgress) put(req *frontendRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.requests[req.queryID] = req
}

// putWithRandomID installs req under a freshly generated, cryptographically
// random queryID, retrying on the astronomically unlikely event of a collision
// with another in-flight request. The chosen ID is returned to the caller so
// it can also be used as the key for later lookup/delete and for cancellation.
func (r *requestsInProgress) putWithRandomID(req *frontendRequest) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var buf [8]byte
	for i := 0; i < 10; i++ {
		if _, err := cryptorand.Read(buf[:]); err != nil {
			return 0, errors.Wrap(err, "failed to generate queryID")
		}
		id := binary.BigEndian.Uint64(buf[:])
		if id == 0 {
			continue
		}
		if _, exists := r.requests[id]; exists {
			continue
		}
		req.queryID = id
		r.requests[id] = req
		return id, nil
	}
	return 0, errors.New("failed to allocate a unique queryID after multiple attempts")
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

package v1

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/weaveworks/common/httpgrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/cortexproject/cortex/pkg/frontend/v1/frontendv1pb"
	"github.com/cortexproject/cortex/pkg/querier/stats"
	"github.com/cortexproject/cortex/pkg/scheduler/queue"
	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util"
	"github.com/cortexproject/cortex/pkg/util/httpgrpcutil"
	"github.com/cortexproject/cortex/pkg/util/services"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

var (
	errTooManyRequest = httpgrpc.Errorf(http.StatusTooManyRequests, "too many outstanding requests")
)

// Config for a Frontend.
type Config struct {
	MaxOutstandingPerTenant int           `yaml:"max_outstanding_per_tenant"`
	QuerierForgetDelay      time.Duration `yaml:"querier_forget_delay"`
}

// RegisterFlags adds the flags required to config this to the given FlagSet.
func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.IntVar(&cfg.MaxOutstandingPerTenant, "querier.max-outstanding-requests-per-tenant", 100, "Maximum number of outstanding requests per tenant per frontend; requests beyond this error with HTTP 429.")
	f.DurationVar(&cfg.QuerierForgetDelay, "query-frontend.querier-forget-delay", 0, "If a querier disconnects without sending notification about graceful shutdown, the query-frontend will keep the querier in the tenant's shard until the forget delay has passed. This feature is useful to reduce the blast radius when shuffle-sharding is enabled.")
}

type Limits interface {
	// Returns max queriers to use per tenant, or 0 if shuffle sharding is disabled.
	MaxQueriersPerUser(user string) int
}

// Frontend queues HTTP requests, dispatches them to backends, and handles retries
// for requests which failed.
type Frontend struct {
	services.Service

	cfg    Config
	log    log.Logger
	limits Limits

	requestQueue *queue.RequestQueue
	activeUsers  *util.ActiveUsersCleanupService

	// Subservices manager.
	subservices        *services.Manager
	subservicesWatcher *services.FailureWatcher

	// Metrics.
	queueLength       *prometheus.GaugeVec
	discardedRequests *prometheus.CounterVec
	numClients        prometheus.GaugeFunc
	queueDuration     prometheus.Histogram
}

type request struct {
	enqueueTime time.Time
	queueSpan   opentracing.Span
	originalCtx context.Context

	request  *httpgrpc.HTTPRequest
	err      chan error
	response chan *httpgrpc.HTTPResponse
}

// New creates a new frontend. Frontend implements service, and must be started and stopped.
func New(cfg Config, limits Limits, log log.Logger, registerer prometheus.Registerer) (*Frontend, error) {
	f := &Frontend{
		cfg:    cfg,
		log:    log,
		limits: limits,
		queueLength: promauto.With(registerer).NewGaugeVec(prometheus.GaugeOpts{
			Name: "cortex_query_frontend_queue_length",
			Help: "Number of queries in the queue.",
		}, []string{"user"}),
		discardedRequests: promauto.With(registerer).NewCounterVec(prometheus.CounterOpts{
			Name: "cortex_query_frontend_discarded_requests_total",
			Help: "Total number of query requests discarded.",
		}, []string{"user"}),
		queueDuration: promauto.With(registerer).NewHistogram(prometheus.HistogramOpts{
			Name:    "cortex_query_frontend_queue_duration_seconds",
			Help:    "Time spend by requests queued.",
			Buckets: prometheus.DefBuckets,
		}),
	}

	f.requestQueue = queue.NewRequestQueue(cfg.MaxOutstandingPerTenant, cfg.QuerierForgetDelay, f.queueLength, f.discardedRequests)
	f.activeUsers = util.NewActiveUsersCleanupWithDefaultValues(f.cleanupInactiveUserMetrics)

	var err error
	f.subservices, err = services.NewManager(f.requestQueue, f.activeUsers)
	if err != nil {
		return nil, err
	}

	f.numClients = promauto.With(registerer).NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cortex_query_frontend_connected_clients",
		Help: "Number of worker clients currently connected to the frontend.",
	}, f.requestQueue.GetConnectedQuerierWorkersMetric)

	f.Service = services.NewBasicService(f.starting, f.running, f.stopping)
	return f, nil
}

func (f *Frontend) starting(ctx context.Context) error {
	f.subservicesWatcher.WatchManager(f.subservices)

	if err := services.StartManagerAndAwaitHealthy(ctx, f.subservices); err != nil {
		return errors.Wrap(err, "unable to start frontend subservices")
	}

	return nil
}

func (f *Frontend) running(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-f.subservicesWatcher.Chan():
			return errors.Wrap(err, "frontend subservice failed")
		}
	}
}

func (f *Frontend) stopping(_ error) error {
	// This will also stop the requests queue, which stop accepting new requests and errors out any pending requests.
	return services.StopManagerAndAwaitStopped(context.Background(), f.subservices)
}

func (f *Frontend) cleanupInactiveUserMetrics(user string) {
	f.queueLength.DeleteLabelValues(user)
	f.discardedRequests.DeleteLabelValues(user)
}

// RoundTripGRPC round trips a proto (instead of a HTTP request).
func (f *Frontend) RoundTripGRPC(ctx context.Context, req *httpgrpc.HTTPRequest) (*httpgrpc.HTTPResponse, error) {
	// Propagate trace context in gRPC too - this will be ignored if using HTTP.
	tracer, span := opentracing.GlobalTracer(), opentracing.SpanFromContext(ctx)
	if tracer != nil && span != nil {
		carrier := (*httpgrpcutil.HttpgrpcHeadersCarrier)(req)
		err := tracer.Inject(span.Context(), opentracing.HTTPHeaders, carrier)
		if err != nil {
			return nil, err
		}
	}

	request := request{
		request:     req,
		originalCtx: ctx,

		// Buffer of 1 to ensure response can be written by the server side
		// of the Process stream, even if this goroutine goes away due to
		// client context cancellation.
		err:      make(chan error, 1),
		response: make(chan *httpgrpc.HTTPResponse, 1),
	}

	if err := f.queueRequest(ctx, &request); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()

	case resp := <-request.response:
		return resp, nil

	case err := <-request.err:
		return nil, err
	}
}

// Process allows backends to pull requests from the frontend.
func (f *Frontend) Process(server frontendv1pb.Frontend_ProcessServer) error {
	querierID, err := getQuerierID(server)
	if err != nil {
		return err
	}

	// Authenticate the querier worker. Reject empty client IDs and, when the
	// gRPC server is configured with verified mTLS client certificates, require
	// that the self-reported ClientID matches the authenticated peer identity.
	// This prevents an unauthenticated peer from registering as a querier and
	// receiving other tenants' queued requests. See CWE-306.
	if err := authenticateQuerier(server.Context(), querierID); err != nil {
		return err
	}

	f.requestQueue.RegisterQuerierConnection(querierID)
	defer f.requestQueue.UnregisterQuerierConnection(querierID)

	// If the downstream request(from querier -> frontend) is cancelled,
	// we need to ping the condition variable to unblock getNextRequestForQuerier.
	// Ideally we'd have ctx aware condition variables...
	go func() {
		<-server.Context().Done()
		f.requestQueue.QuerierDisconnecting()
	}()

	lastUserIndex := queue.FirstUser()

	for {
		reqWrapper, idx, err := f.requestQueue.GetNextRequestForQuerier(server.Context(), lastUserIndex, querierID)
		if err != nil {
			return err
		}
		lastUserIndex = idx

		req := reqWrapper.(*request)

		f.queueDuration.Observe(time.Since(req.enqueueTime).Seconds())
		req.queueSpan.Finish()

		/*
		  We want to dequeue the next unexpired request from the chosen tenant queue.
		  The chance of choosing a particular tenant for dequeueing is (1/active_tenants).
		  This is problematic under load, especially with other middleware enabled such as
		  querier.split-by-interval, where one request may fan out into many.
		  If expired requests aren't exhausted before checking another tenant, it would take
		  n_active_tenants * n_expired_requests_at_front_of_queue requests being processed
		  before an active request was handled for the tenant in question.
		  If this tenant meanwhile continued to queue requests,
		  it's possible that it's own queue would perpetually contain only expired requests.
		*/
		if req.originalCtx.Err() != nil {
			lastUserIndex = lastUserIndex.ReuseLastUser()
			continue
		}

		// Handle the stream sending & receiving on a goroutine so we can
		// monitoring the contexts in a select and cancel things appropriately.
		resps := make(chan *frontendv1pb.ClientToFrontend, 1)
		errs := make(chan error, 1)
		go func() {
			err = server.Send(&frontendv1pb.FrontendToClient{
				Type:         frontendv1pb.HTTP_REQUEST,
				HttpRequest:  req.request,
				StatsEnabled: stats.IsEnabled(req.originalCtx),
			})
			if err != nil {
				errs <- err
				return
			}

			resp, err := server.Recv()
			if err != nil {
				errs <- err
				return
			}

			resps <- resp
		}()

		select {
		// If the upstream request is cancelled, we need to cancel the
		// downstream req.  Only way we can do that is to close the stream.
		// The worker client is expecting this semantics.
		case <-req.originalCtx.Done():
			return req.originalCtx.Err()

		// Is there was an error handling this request due to network IO,
		// then error out this upstream request _and_ stream.
		case err := <-errs:
			req.err <- err
			return err

		// Happy path: merge the stats and propagate the response.
		case resp := <-resps:
			if stats.ShouldTrackHTTPGRPCResponse(resp.HttpResponse) {
				stats := stats.FromContext(req.originalCtx)
				stats.Merge(resp.Stats) // Safe if stats is nil.
			}

			req.response <- resp.HttpResponse
		}
	}
}

func (f *Frontend) NotifyClientShutdown(ctx context.Context, req *frontendv1pb.NotifyClientShutdownRequest) (*frontendv1pb.NotifyClientShutdownResponse, error) {
	// Authenticate the shutdown notification against the peer identity so an
	// untrusted caller cannot de-register another querier's connection state.
	if err := authenticateQuerier(ctx, req.GetClientID()); err != nil {
		return nil, err
	}

	level.Info(f.log).Log("msg", "received shutdown notification from querier", "querier", req.GetClientID())
	f.requestQueue.NotifyQuerierShutdown(req.GetClientID())

	return &frontendv1pb.NotifyClientShutdownResponse{}, nil
}

func getQuerierID(server frontendv1pb.Frontend_ProcessServer) (string, error) {
	err := server.Send(&frontendv1pb.FrontendToClient{
		Type: frontendv1pb.GET_ID,
		// Old queriers don't support GET_ID, and will try to use the request.
		// To avoid confusing them, include dummy request.
		HttpRequest: &httpgrpc.HTTPRequest{
			Method: "GET",
			Url:    "/invalid_request_sent_by_frontend",
		},
	})

	if err != nil {
		return "", err
	}

	resp, err := server.Recv()
	if err != nil {
		return "", err
	}

	// Reject queriers that do not identify themselves. Historically Cortex
	// tolerated an empty ClientID (treating all such workers as a single
	// synthetic querier) which allowed any gRPC peer to attach to the Process
	// stream and receive queued requests belonging to arbitrary tenants.
	clientID := resp.GetClientID()
	if clientID == "" {
		return "", status.Error(codes.Unauthenticated, "querier did not report a ClientID")
	}
	return clientID, nil
}

// authenticatedPeerIdentity returns a stable identity derived from the
// verified mTLS client certificate presented by the gRPC peer, or an empty
// string when the connection is not authenticated with a verified client
// certificate. The identity is taken from the certificate CommonName, falling
// back to the first DNS SAN or URI SAN when CommonName is empty. Only chains
// that gRPC has already verified (TLSInfo.State.VerifiedChains) are considered.
func authenticatedPeerIdentity(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.AuthInfo == nil {
		return ""
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ""
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return ""
	}
	cert := tlsInfo.State.VerifiedChains[0][0]
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	for _, u := range cert.URIs {
		if u != nil {
			return u.String()
		}
	}
	return ""
}

// authenticateQuerier verifies that the self-reported querier/client ID is
// non-empty and, when the gRPC server is terminating verified mTLS, that it
// matches the authenticated peer identity. If no verified client certificate
// is presented (e.g. mTLS is not configured, which is the historical default),
// only the non-empty requirement is enforced; operators relying on this code
// path must still provide perimeter authentication / network isolation and
// should enable `-server.grpc-tls-client-auth=RequireAndVerifyClientCert` to
// obtain cryptographic peer authentication.
func authenticateQuerier(ctx context.Context, reportedID string) error {
	if reportedID == "" {
		return status.Error(codes.Unauthenticated, "querier did not report a ClientID")
	}
	if peerID := authenticatedPeerIdentity(ctx); peerID != "" && peerID != reportedID {
		return status.Errorf(codes.PermissionDenied, "querier ClientID %q does not match authenticated peer identity", reportedID)
	}
	return nil
}

func (f *Frontend) queueRequest(ctx context.Context, req *request) error {
	tenantIDs, err := tenant.TenantIDs(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	req.enqueueTime = now
	req.queueSpan, _ = opentracing.StartSpanFromContext(ctx, "queued")

	// aggregate the max queriers limit in the case of a multi tenant query
	maxQueriers := validation.SmallestPositiveNonZeroIntPerTenant(tenantIDs, f.limits.MaxQueriersPerUser)

	joinedTenantID := tenant.JoinTenantIDs(tenantIDs)
	f.activeUsers.UpdateUserTimestamp(joinedTenantID, now)

	err = f.requestQueue.EnqueueRequest(joinedTenantID, req, maxQueriers, nil)
	if err == queue.ErrTooManyRequests {
		return errTooManyRequest
	}
	return err
}

// CheckReady determines if the query frontend is ready.  Function parameters/return
// chosen to match the same method in the ingester
func (f *Frontend) CheckReady(_ context.Context) error {
	// if we have more than one querier connected we will consider ourselves ready
	connectedClients := f.requestQueue.GetConnectedQuerierWorkersMetric()
	if connectedClients > 0 {
		return nil
	}

	msg := fmt.Sprintf("not ready: number of queriers connected to query-frontend is %d", int64(connectedClients))
	level.Info(f.log).Log("msg", msg)
	return errors.New(msg)
}

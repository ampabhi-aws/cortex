package queue

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/atomic"

	"github.com/cortexproject/cortex/pkg/tenant"
	"github.com/cortexproject/cortex/pkg/util/services"
)

const (
	// How frequently to check for disconnected queriers that should be forgotten.
	forgetCheckPeriod = 5 * time.Second
)

var (
	ErrTooManyRequests = errors.New("too many outstanding requests")
	ErrStopped         = errors.New("queue is stopped")
	errInvalidTenantID = errors.New("invalid tenant ID")
)

// tenantIDJoinSeparator mirrors tenant.JoinTenantIDs: multi-tenant requests arrive at
// the queue with each tenant ID separated by this character, so we must validate each
// component independently.
const tenantIDJoinSeparator = "|"

// UserIndex is opaque type that allows to resume iteration over users between successive calls
// of RequestQueue.GetNextRequestForQuerier method.
type UserIndex struct {
	last int
}

// Modify index to start iteration on the same user, for which last queue was returned.
func (ui UserIndex) ReuseLastUser() UserIndex {
	if ui.last >= 0 {
		return UserIndex{last: ui.last - 1}
	}
	return ui
}

// FirstUser returns UserIndex that starts iteration over user queues from the very first user.
func FirstUser() UserIndex {
	return UserIndex{last: -1}
}

// Request stored into the queue.
type Request interface{}

// RequestQueue holds incoming requests in per-user queues. It also assigns each user specified number of queriers,
// and when querier asks for next request to handle (using GetNextRequestForQuerier), it returns requests
// in a fair fashion.
type RequestQueue struct {
	services.Service

	connectedQuerierWorkers *atomic.Int32

	mtx     sync.Mutex
	cond    *sync.Cond // Notified when request is enqueued or dequeued, or querier is disconnected.
	queues  *queues
	stopped bool

	// Aggregate cap on the total number of queued (outstanding) requests across all
	// per-tenant queues. 0 disables the cap. This protects against a caller rotating
	// the tenant string to bypass the per-tenant MaxOutstandingPerTenant allowance.
	maxOutstandingTotal int
	outstandingTotal    int

	queueLength       *prometheus.GaugeVec   // Per user and reason.
	discardedRequests *prometheus.CounterVec // Per user.
}

func NewRequestQueue(maxOutstandingPerTenant int, forgetDelay time.Duration, queueLength *prometheus.GaugeVec, discardedRequests *prometheus.CounterVec) *RequestQueue {
	return NewRequestQueueWithLimits(maxOutstandingPerTenant, forgetDelay, 0, 0, queueLength, discardedRequests)
}

// NewRequestQueueWithLimits creates a RequestQueue with the aggregate (non per-tenant) caps.
// maxTenantQueues bounds the number of simultaneously live tenant queues, and
// maxOutstandingTotal bounds the number of outstanding (queued) requests across all tenants.
// Zero (or negative) means the corresponding aggregate cap is disabled.
func NewRequestQueueWithLimits(maxOutstandingPerTenant int, forgetDelay time.Duration, maxTenantQueues int, maxOutstandingTotal int, queueLength *prometheus.GaugeVec, discardedRequests *prometheus.CounterVec) *RequestQueue {
	if maxOutstandingTotal < 0 {
		maxOutstandingTotal = 0
	}
	q := &RequestQueue{
		queues:                  newUserQueuesWithLimits(maxOutstandingPerTenant, forgetDelay, maxTenantQueues),
		connectedQuerierWorkers: atomic.NewInt32(0),
		maxOutstandingTotal:     maxOutstandingTotal,
		queueLength:             queueLength,
		discardedRequests:       discardedRequests,
	}

	q.cond = sync.NewCond(&q.mtx)
	q.Service = services.NewTimerService(forgetCheckPeriod, nil, q.forgetDisconnectedQueriers, q.stopping).WithName("request queue")

	return q
}

// EnqueueRequest puts the request into the queue. MaxQueries is user-specific value that specifies how many queriers can
// this user use (zero or negative = all queriers). It is passed to each EnqueueRequest, because it can change
// between calls.
//
// If request is successfully enqueued, successFn is called with the lock held, before any querier can receive the request.
func (q *RequestQueue) EnqueueRequest(userID string, req Request, maxQueriers int, successFn func()) error {
	// Reject caller-supplied tenant identities that fail the documented tenant-ID
	// character/length rules (tenant.ValidTenantID) before taking any locks, creating
	// a queue or emitting per-tenant metric labels. This prevents a client that controls
	// X-Scope-OrgID (or FrontendLoop UserID) from minting arbitrary queue identities.
	if err := validateTenantID(userID); err != nil {
		return err
	}

	q.mtx.Lock()
	defer q.mtx.Unlock()

	if q.stopped {
		return ErrStopped
	}

	// Enforce the aggregate outstanding-request cap before touching per-tenant state,
	// so a caller rotating the tenant string cannot multiply the per-tenant allowance.
	if q.maxOutstandingTotal > 0 && q.outstandingTotal >= q.maxOutstandingTotal {
		q.discardedRequests.WithLabelValues(userID).Inc()
		return ErrTooManyRequests
	}

	queue := q.queues.getOrAddQueue(userID, maxQueriers)
	if queue == nil {
		// Either userID is "" or we have hit the aggregate per-tenant-queue cap.
		if userID == "" {
			return errors.New("no queue found")
		}
		q.discardedRequests.WithLabelValues(userID).Inc()
		return ErrTooManyRequests
	}

	select {
	case queue <- req:
		q.outstandingTotal++
		q.queueLength.WithLabelValues(userID).Inc()
		q.cond.Broadcast()
		// Call this function while holding a lock. This guarantees that no querier can fetch the request before function returns.
		if successFn != nil {
			successFn()
		}
		return nil
	default:
		q.discardedRequests.WithLabelValues(userID).Inc()
		return ErrTooManyRequests
	}
}

// validateTenantID enforces the tenant ID character and length rules on the
// value used to key the queue. It accepts the multi-tenant joined form (`a|b|c`)
// produced by tenant.JoinTenantIDs by validating each component.
func validateTenantID(userID string) error {
	if userID == "" {
		return errInvalidTenantID
	}
	for _, id := range strings.Split(userID, tenantIDJoinSeparator) {
		if id == "" {
			return errInvalidTenantID
		}
		if err := tenant.ValidTenantID(id); err != nil {
			return errInvalidTenantID
		}
	}
	return nil
}

// GetNextRequestForQuerier find next user queue and takes the next request off of it. Will block if there are no requests.
// By passing user index from previous call of this method, querier guarantees that it iterates over all users fairly.
// If querier finds that request from the user is already expired, it can get a request for the same user by using UserIndex.ReuseLastUser.
func (q *RequestQueue) GetNextRequestForQuerier(ctx context.Context, last UserIndex, querierID string) (Request, UserIndex, error) {
	q.mtx.Lock()
	defer q.mtx.Unlock()

	querierWait := false

FindQueue:
	// We need to wait if there are no users, or no pending requests for given querier.
	for (q.queues.len() == 0 || querierWait) && ctx.Err() == nil && !q.stopped {
		querierWait = false
		q.cond.Wait()
	}

	if q.stopped {
		return nil, last, ErrStopped
	}

	if err := ctx.Err(); err != nil {
		return nil, last, err
	}

	for {
		queue, userID, idx := q.queues.getNextQueueForQuerier(last.last, querierID)
		last.last = idx
		if queue == nil {
			break
		}

		// Pick next request from the queue.
		for {
			request := <-queue
			if len(queue) == 0 {
				q.queues.deleteQueue(userID)
			}

			if q.outstandingTotal > 0 {
				q.outstandingTotal--
			}
			q.queueLength.WithLabelValues(userID).Dec()

			// Tell close() we've processed a request.
			q.cond.Broadcast()

			return request, last, nil
		}
	}

	// There are no unexpired requests, so we can get back
	// and wait for more requests.
	querierWait = true
	goto FindQueue
}

func (q *RequestQueue) forgetDisconnectedQueriers(_ context.Context) error {
	q.mtx.Lock()
	defer q.mtx.Unlock()

	if q.queues.forgetDisconnectedQueriers(time.Now()) > 0 {
		// We need to notify goroutines cause having removed some queriers
		// may have caused a resharding.
		q.cond.Broadcast()
	}

	return nil
}

func (q *RequestQueue) stopping(_ error) error {
	q.mtx.Lock()
	defer q.mtx.Unlock()

	for q.queues.len() > 0 && q.connectedQuerierWorkers.Load() > 0 {
		q.cond.Wait()
	}

	// Only stop after dispatching enqueued requests.
	q.stopped = true

	// If there are still goroutines in GetNextRequestForQuerier method, they get notified.
	q.cond.Broadcast()

	return nil
}

func (q *RequestQueue) RegisterQuerierConnection(querier string) {
	q.connectedQuerierWorkers.Inc()

	q.mtx.Lock()
	defer q.mtx.Unlock()
	q.queues.addQuerierConnection(querier)
}

func (q *RequestQueue) UnregisterQuerierConnection(querier string) {
	q.connectedQuerierWorkers.Dec()

	q.mtx.Lock()
	defer q.mtx.Unlock()
	q.queues.removeQuerierConnection(querier, time.Now())
}

func (q *RequestQueue) NotifyQuerierShutdown(querierID string) {
	q.mtx.Lock()
	defer q.mtx.Unlock()
	q.queues.notifyQuerierShutdown(querierID)
}

// When querier is waiting for next request, this unblocks the method.
func (q *RequestQueue) QuerierDisconnecting() {
	q.cond.Broadcast()
}

func (q *RequestQueue) GetConnectedQuerierWorkersMetric() float64 {
	return float64(q.connectedQuerierWorkers.Load())
}

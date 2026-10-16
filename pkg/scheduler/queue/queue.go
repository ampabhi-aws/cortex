package queue

import (
	"context"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/atomic"

	"github.com/cortexproject/cortex/pkg/util/services"
)

const (
	// How frequently to check for disconnected queriers that should be forgotten.
	forgetCheckPeriod = 5 * time.Second
)

var (
	ErrTooManyRequests = errors.New("too many outstanding requests")
	ErrTooManyTenants  = errors.New("too many tenants with outstanding requests")
	ErrStopped         = errors.New("queue is stopped")
)

// sizedRequest is an optional interface implemented by Request types. When implemented, the
// RequestQueue counts queued bytes per tenant and refuses enqueues that would exceed the
// configured per-tenant queued-bytes budget (in addition to the per-tenant outstanding-request
// cap). Returning a non-positive value causes byte accounting for that request to be skipped.
type sizedRequest interface {
	Size() int
}

// cancellableRequest is an optional interface implemented by Request types. When implemented,
// EnqueueRequest will drop a request whose context is already cancelled rather than keeping
// its payload in the per-tenant channel until a dequeue would discard it.
type cancellableRequest interface {
	Context() context.Context
}

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

	queueLength       *prometheus.GaugeVec   // Per user and reason.
	discardedRequests *prometheus.CounterVec // Per user.
}

// NewRequestQueue builds a RequestQueue with the per-tenant outstanding-request cap and
// forget-delay. maxUsers and maxUserQueuedBytes default to 0 (disabled); use
// NewRequestQueueWithLimits to configure the global tenant cap and per-tenant queued-bytes
// budget that bound queue state against untrusted/attacker-controlled tenant IDs.
func NewRequestQueue(maxOutstandingPerTenant int, forgetDelay time.Duration, queueLength *prometheus.GaugeVec, discardedRequests *prometheus.CounterVec) *RequestQueue {
	return NewRequestQueueWithLimits(maxOutstandingPerTenant, 0, 0, forgetDelay, queueLength, discardedRequests)
}

// NewRequestQueueWithLimits builds a RequestQueue with explicit bounds on the number of
// concurrently queued tenants (maxUsers; 0 disables) and on the total bytes buffered per
// tenant (maxUserQueuedBytes; 0 disables). These are the volumetric guards that prevent an
// untrusted peer from inflating per-tenant queue state via distinct caller-supplied tenant
// IDs or over-sized request bodies.
func NewRequestQueueWithLimits(maxOutstandingPerTenant, maxUsers, maxUserQueuedBytes int, forgetDelay time.Duration, queueLength *prometheus.GaugeVec, discardedRequests *prometheus.CounterVec) *RequestQueue {
	q := &RequestQueue{
		queues:                  newUserQueuesWithLimits(maxOutstandingPerTenant, maxUsers, maxUserQueuedBytes, forgetDelay),
		connectedQuerierWorkers: atomic.NewInt32(0),
		queueLength:             queueLength,
		discardedRequests:       discardedRequests,
	}

	q.cond = sync.NewCond(&q.mtx)
	q.Service = services.NewTimerService(forgetCheckPeriod, nil, q.forgetDisconnectedQueriers, q.stopping).WithName("request queue")

	return q
}

// requestSize returns the Size() of req when it implements sizedRequest, otherwise 0. A
// non-positive size is also normalised to 0 so byte accounting is a no-op for that request.
func requestSize(req Request) int {
	if sr, ok := req.(sizedRequest); ok {
		n := sr.Size()
		if n > 0 {
			return n
		}
	}
	return 0
}

// requestCancelled reports whether req carries a context (via the cancellableRequest optional
// interface) that has already been cancelled.
func requestCancelled(req Request) bool {
	cr, ok := req.(cancellableRequest)
	if !ok {
		return false
	}
	ctx := cr.Context()
	if ctx == nil {
		return false
	}
	return ctx.Err() != nil
}

// EnqueueRequest puts the request into the queue. MaxQueries is user-specific value that specifies how many queriers can
// this user use (zero or negative = all queriers). It is passed to each EnqueueRequest, because it can change
// between calls.
//
// If request is successfully enqueued, successFn is called with the lock held, before any querier can receive the request.
func (q *RequestQueue) EnqueueRequest(userID string, req Request, maxQueriers int, successFn func()) error {
	// Fast-path: if the request's context is already cancelled, drop it before taking the
	// global mutex so that a cancelled request never pins a channel slot or request payload.
	if requestCancelled(req) {
		q.discardedRequests.WithLabelValues(userID).Inc()
		return context.Canceled
	}

	q.mtx.Lock()
	defer q.mtx.Unlock()

	if q.stopped {
		return ErrStopped
	}

	queue := q.queues.getOrAddQueue(userID, maxQueriers)
	if queue == nil {
		if userID == "" {
			// This can only happen if userID is "".
			return errors.New("no queue found")
		}
		// Global tenant cap reached: refuse to allocate a new per-tenant queue so that an
		// untrusted peer cannot inflate the scheduler's tenant set.
		q.discardedRequests.WithLabelValues(userID).Inc()
		return ErrTooManyTenants
	}

	// Enforce the per-tenant queued-bytes budget, when configured and the request reports its
	// size, in addition to the per-tenant channel capacity.
	size := requestSize(req)
	if q.queues.maxUserQueuedBytes > 0 && size > 0 {
		uq := q.queues.userQueues[userID]
		if uq.queuedBytes+int64(size) > int64(q.queues.maxUserQueuedBytes) {
			q.discardedRequests.WithLabelValues(userID).Inc()
			return ErrTooManyRequests
		}
	}

	select {
	case queue <- req:
		if size > 0 {
			q.queues.userQueues[userID].queuedBytes += int64(size)
		}
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
			uq := q.queues.userQueues[userID]
			if uq != nil {
				if size := requestSize(request); size > 0 {
					uq.queuedBytes -= int64(size)
					if uq.queuedBytes < 0 {
						uq.queuedBytes = 0
					}
				}
			}
			if len(queue) == 0 {
				q.queues.deleteQueue(userID)
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

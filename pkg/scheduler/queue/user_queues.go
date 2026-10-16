package queue

import (
	"math/rand"
	"sort"
	"time"

	"github.com/cortexproject/cortex/pkg/util"
)

// querier holds information about a querier registered in the queue.
type querier struct {
	// Number of active connections.
	connections int

	// True if the querier notified it's gracefully shutting down.
	shuttingDown bool

	// When the last connection has been unregistered.
	disconnectedAt time.Time
}

// This struct holds user queues for pending requests. It also keeps track of connected queriers,
// and mapping between users and queriers.
type queues struct {
	userQueues map[string]*userQueue

	// List of all users with queues, used for iteration when searching for next queue to handle.
	// Users removed from the middle are replaced with "". To avoid skipping users during iteration, we only shrink
	// this list when there are ""'s at the end of it.
	users []string

	maxUserQueueSize int

	// Maximum number of concurrently queued tenants. 0 disables the cap. When reached,
	// getOrAddQueue refuses to allocate a new per-tenant queue so that an attacker-controlled
	// tenant ID cannot inflate the scheduler's tenant set without bound.
	maxUsers int

	// Maximum number of bytes that can be concurrently queued per-tenant across the per-tenant
	// channel. 0 disables the byte accounting. When set, EnqueueRequest also refuses enqueues
	// whose Size() would cause the per-tenant queued-bytes total to exceed this budget.
	maxUserQueuedBytes int

	// How long to wait before removing a querier which has got disconnected
	// but hasn't notified about a graceful shutdown.
	forgetDelay time.Duration

	// Tracks queriers registered to the queue.
	queriers map[string]*querier

	// Sorted list of querier names, used when creating per-user shard.
	sortedQueriers []string

	// Monotonic version bumped every time the set of sortedQueriers changes. Per-tenant shard
	// assignments are recomputed lazily when a tenant is next touched and its stored version
	// does not match this one. This replaces the previous O(tenants) pass that was done under
	// the global queue mutex on every querier connect/disconnect.
	queriersVersion int64
}

type userQueue struct {
	ch chan Request

	// Running total of the Size() of requests currently buffered in ch, when the Request type
	// implements sizedRequest. Used to enforce a per-tenant queued-bytes budget in addition to
	// the per-tenant outstanding-request count.
	queuedBytes int64

	// If not nil, only these queriers can handle user requests. If nil, all queriers can.
	// We set this to nil if number of available queriers <= maxQueriers.
	queriers    map[string]struct{}
	maxQueriers int

	// Value of queues.queriersVersion at the time queriers was last recomputed. If it does not
	// match the parent queues' queriersVersion, queriers is stale and must be refreshed before
	// use.
	queriersVersion int64

	// Seed for shuffle sharding of queriers. This seed is based on userID only and is therefore consistent
	// between different frontends.
	seed int64

	// Points back to 'users' field in queues. Enables quick cleanup.
	index int
}

func newUserQueues(maxUserQueueSize int, forgetDelay time.Duration) *queues {
	return newUserQueuesWithLimits(maxUserQueueSize, 0, 0, forgetDelay)
}

func newUserQueuesWithLimits(maxUserQueueSize, maxUsers, maxUserQueuedBytes int, forgetDelay time.Duration) *queues {
	return &queues{
		userQueues:         map[string]*userQueue{},
		users:              nil,
		maxUserQueueSize:   maxUserQueueSize,
		maxUsers:           maxUsers,
		maxUserQueuedBytes: maxUserQueuedBytes,
		forgetDelay:        forgetDelay,
		queriers:           map[string]*querier{},
		sortedQueriers:     nil,
	}
}

func (q *queues) len() int {
	return len(q.userQueues)
}

func (q *queues) deleteQueue(userID string) {
	uq := q.userQueues[userID]
	if uq == nil {
		return
	}

	delete(q.userQueues, userID)
	q.users[uq.index] = ""

	// Shrink users list size if possible. This is safe, and no users will be skipped during iteration.
	for ix := len(q.users) - 1; ix >= 0 && q.users[ix] == ""; ix-- {
		q.users = q.users[:ix]
	}
}

// Returns existing or new queue for user.
// MaxQueriers is used to compute which queriers should handle requests for this user.
// If maxQueriers is <= 0, all queriers can handle this user's requests.
// If maxQueriers has changed since the last call, queriers for this are recomputed.
// Returns nil if userID is empty or if a new queue would exceed the configured maxUsers cap.
func (q *queues) getOrAddQueue(userID string, maxQueriers int) chan Request {
	// Empty user is not allowed, as that would break our users list ("" is used for free spot).
	if userID == "" {
		return nil
	}

	if maxQueriers < 0 {
		maxQueriers = 0
	}

	uq := q.userQueues[userID]

	if uq == nil {
		// Enforce the global tenant cap: refuse to allocate state for yet another tenant ID when
		// the configured maximum has been reached. Combined with the per-tenant outstanding
		// limits this bounds the scheduler's queue state against an attacker who presents
		// an unbounded number of distinct tenant IDs.
		if q.maxUsers > 0 && len(q.userQueues) >= q.maxUsers {
			return nil
		}

		uq = &userQueue{
			ch:    make(chan Request, q.maxUserQueueSize),
			seed:  util.ShuffleShardSeed(userID, ""),
			index: -1,
		}
		q.userQueues[userID] = uq

		// Add user to the list of users... find first free spot, and put it there.
		for ix, u := range q.users {
			if u == "" {
				uq.index = ix
				q.users[ix] = userID
				break
			}
		}

		// ... or add to the end.
		if uq.index < 0 {
			uq.index = len(q.users)
			q.users = append(q.users, userID)
		}
	}

	if uq.maxQueriers != maxQueriers {
		uq.maxQueriers = maxQueriers
		uq.queriers = shuffleQueriersForUser(uq.seed, maxQueriers, q.sortedQueriers, nil)
		uq.queriersVersion = q.queriersVersion
	} else {
		// Refresh lazily if the global queriers set has changed since we last computed this
		// tenant's assignment.
		q.refreshUserQueriersLocked(uq)
	}

	return uq.ch
}

// refreshUserQueriersLocked recomputes a single tenant's querier assignment if the global
// queriers set has changed since it was last computed. It must be called with the parent
// RequestQueue mutex held.
func (q *queues) refreshUserQueriersLocked(uq *userQueue) {
	if uq.queriersVersion == q.queriersVersion {
		return
	}
	uq.queriers = shuffleQueriersForUser(uq.seed, uq.maxQueriers, q.sortedQueriers, nil)
	uq.queriersVersion = q.queriersVersion
}

// Finds next queue for the querier. To support fair scheduling between users, client is expected
// to pass last user index returned by this function as argument. Is there was no previous
// last user index, use -1.
func (q *queues) getNextQueueForQuerier(lastUserIndex int, querierID string) (chan Request, string, int) {
	uid := lastUserIndex

	for iters := 0; iters < len(q.users); iters++ {
		uid = uid + 1

		// Don't use "mod len(q.users)", as that could skip users at the beginning of the list
		// for example when q.users has shrunk since last call.
		if uid >= len(q.users) {
			uid = 0
		}

		u := q.users[uid]
		if u == "" {
			continue
		}

		uq := q.userQueues[u]
		// Lazily materialise this tenant's querier assignment before using it.
		q.refreshUserQueriersLocked(uq)

		if uq.queriers != nil {
			if _, ok := uq.queriers[querierID]; !ok {
				// This querier is not handling the user.
				continue
			}
		}

		return uq.ch, u, uid
	}
	return nil, "", uid
}

func (q *queues) addQuerierConnection(querierID string) {
	info := q.queriers[querierID]
	if info != nil {
		info.connections++

		// Reset in case the querier re-connected while it was in the forget waiting period.
		info.shuttingDown = false
		info.disconnectedAt = time.Time{}

		return
	}

	// First connection from this querier.
	q.queriers[querierID] = &querier{connections: 1}
	q.sortedQueriers = append(q.sortedQueriers, querierID)
	sort.Strings(q.sortedQueriers)

	// Invalidate per-tenant querier assignments. They are refreshed lazily per-tenant when the
	// tenant is next touched, so this is O(1) rather than O(tenants) while holding the global
	// RequestQueue mutex.
	q.queriersVersion++
}

func (q *queues) removeQuerierConnection(querierID string, now time.Time) {
	info := q.queriers[querierID]
	if info == nil || info.connections <= 0 {
		panic("unexpected number of connections for querier")
	}

	// Decrease the number of active connections.
	info.connections--
	if info.connections > 0 {
		return
	}

	// There no more active connections. If the forget delay is configured then
	// we can remove it only if querier has announced a graceful shutdown.
	if info.shuttingDown || q.forgetDelay == 0 {
		q.removeQuerier(querierID)
		return
	}

	// No graceful shutdown has been notified yet, so we should track the current time
	// so that we'll remove the querier as soon as we receive the graceful shutdown
	// notification (if any) or once the threshold expires.
	info.disconnectedAt = now
}

func (q *queues) removeQuerier(querierID string) {
	delete(q.queriers, querierID)

	ix := sort.SearchStrings(q.sortedQueriers, querierID)
	if ix >= len(q.sortedQueriers) || q.sortedQueriers[ix] != querierID {
		panic("incorrect state of sorted queriers")
	}

	q.sortedQueriers = append(q.sortedQueriers[:ix], q.sortedQueriers[ix+1:]...)

	// Invalidate per-tenant querier assignments; they are refreshed lazily.
	q.queriersVersion++
}

// notifyQuerierShutdown records that a querier has sent notification about a graceful shutdown.
func (q *queues) notifyQuerierShutdown(querierID string) {
	info := q.queriers[querierID]
	if info == nil {
		// The querier may have already been removed, so we just ignore it.
		return
	}

	// If there are no more connections, we should remove the querier.
	if info.connections == 0 {
		q.removeQuerier(querierID)
		return
	}

	// Otherwise we should annotate we received a graceful shutdown notification
	// and the querier will be removed once all connections are unregistered.
	info.shuttingDown = true
}

// forgetDisconnectedQueriers removes all disconnected queriers that have gone since at least
// the forget delay. Returns the number of forgotten queriers.
func (q *queues) forgetDisconnectedQueriers(now time.Time) int {
	// Nothing to do if the forget delay is disabled.
	if q.forgetDelay == 0 {
		return 0
	}

	// Remove all queriers with no connections that have gone since at least the forget delay.
	threshold := now.Add(-q.forgetDelay)
	forgotten := 0

	for querierID := range q.queriers {
		if info := q.queriers[querierID]; info.connections == 0 && info.disconnectedAt.Before(threshold) {
			q.removeQuerier(querierID)
			forgotten++
		}
	}

	return forgotten
}

// shuffleQueriersForUser returns nil if queriersToSelect is 0 or there are not enough queriers to select from.
// In that case *all* queriers should be used.
// Scratchpad is used for shuffling, to avoid new allocations. If nil, new slice is allocated.
func shuffleQueriersForUser(userSeed int64, queriersToSelect int, allSortedQueriers []string, scratchpad []string) map[string]struct{} {
	if queriersToSelect == 0 || len(allSortedQueriers) <= queriersToSelect {
		return nil
	}

	result := make(map[string]struct{}, queriersToSelect)
	rnd := rand.New(rand.NewSource(userSeed))

	scratchpad = scratchpad[:0]
	scratchpad = append(scratchpad, allSortedQueriers...)

	last := len(scratchpad) - 1
	for i := 0; i < queriersToSelect; i++ {
		r := rnd.Intn(last + 1)
		result[scratchpad[r]] = struct{}{}
		// move selected item to the end, it won't be selected anymore.
		scratchpad[r], scratchpad[last] = scratchpad[last], scratchpad[r]
		last--
	}

	return result
}

package ring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/ring/kv/consul"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// newTestRing returns a Ring backed by an in-memory consul KV client, seeded
// with a single ingester, so the forget code path has something to delete.
func newTestRing(t *testing.T, enableForget bool) (*Ring, func()) {
	t.Helper()

	store, closer := consul.NewInMemoryClient(GetCodec(), log.NewNopLogger(), nil)

	var cfg Config
	flagext.DefaultValues(&cfg)
	cfg.KVStore.Mock = store
	cfg.EnableForgetEndpoint = enableForget

	r, err := NewWithStoreClientAndStrategy(cfg, "test", "test-ring", store, NewDefaultReplicationStrategy(), nil, log.NewNopLogger())
	require.NoError(t, err)

	// Seed the ring with one instance so we can observe whether a POST
	// mutates it.
	require.NoError(t, store.CAS(context.Background(), "test-ring", func(_ interface{}) (interface{}, bool, error) {
		d := NewDesc()
		d.AddIngester("instance-1", "1.2.3.4", "zone-a", []uint32{1}, ACTIVE, time.Unix(1600000000, 0))
		return d, true, nil
	}))

	// Populate the in-memory ringDesc so ServeHTTP can render without going
	// through the lifecycle service.
	val, err := store.Get(context.Background(), "test-ring")
	require.NoError(t, err)
	r.updateRingState(val.(*Desc))

	cleanup := func() { _ = closer.Close() }
	return r, cleanup
}

// TestServeHTTP_RejectsPOST confirms the public ring status handler no longer
// accepts POST, so an unauthenticated client cannot mutate the ring through
// the GET page URL.
func TestServeHTTP_RejectsPOST(t *testing.T) {
	r, cleanup := newTestRing(t, true /* even when forget is enabled */)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/ingester/ring", strings.NewReader("forget=instance-1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	// The ring must be unchanged.
	val, err := r.KVClient.Get(context.Background(), "test-ring")
	require.NoError(t, err)
	desc := val.(*Desc)
	_, present := desc.Ingesters["instance-1"]
	assert.True(t, present, "POST to the read-only ring page must not remove instances")
}

// TestForgetHandler_DisabledByDefault confirms the destructive handler is
// off unless the operator explicitly enables it, independent of auth.
func TestForgetHandler_DisabledByDefault(t *testing.T) {
	r, cleanup := newTestRing(t, false)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/ingester/ring/forget", strings.NewReader("forget=instance-1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	r.ForgetHandler(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)

	val, err := r.KVClient.Get(context.Background(), "test-ring")
	require.NoError(t, err)
	desc := val.(*Desc)
	_, present := desc.Ingesters["instance-1"]
	assert.True(t, present, "forget must not mutate the ring when the endpoint is disabled")
}

// TestForgetHandler_RejectsNonPOST ensures GET on the forget URL is a 405.
func TestForgetHandler_RejectsNonPOST(t *testing.T) {
	r, cleanup := newTestRing(t, true)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/ingester/ring/forget", nil)
	rec := httptest.NewRecorder()
	r.ForgetHandler(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestForgetHandler_EmptyIDRejected confirms the destructive handler refuses
// requests without an instance id so a bogus POST cannot force a KV write.
func TestForgetHandler_EmptyIDRejected(t *testing.T) {
	r, cleanup := newTestRing(t, true)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/ingester/ring/forget", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ForgetHandler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestForgetHandler_UnknownIDIsNoop confirms a POST naming an id that is not
// in the ring does not force a KV descriptor rewrite.
func TestForgetHandler_UnknownIDIsNoop(t *testing.T) {
	r, cleanup := newTestRing(t, true)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/ingester/ring/forget", strings.NewReader("forget=does-not-exist"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ForgetHandler(rec, req)

	// Successful (no-op) response path -- 302 like the mutating path, but no
	// KV write happens.
	assert.Equal(t, http.StatusFound, rec.Code)

	val, err := r.KVClient.Get(context.Background(), "test-ring")
	require.NoError(t, err)
	desc := val.(*Desc)
	assert.Len(t, desc.Ingesters, 1, "forget of an unknown id must leave the ring unchanged")
}

// TestForgetHandler_RemovesKnownInstance confirms the happy path still works
// when the endpoint is enabled.
func TestForgetHandler_RemovesKnownInstance(t *testing.T) {
	r, cleanup := newTestRing(t, true)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/ingester/ring/forget", strings.NewReader("forget=instance-1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ForgetHandler(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)

	val, err := r.KVClient.Get(context.Background(), "test-ring")
	require.NoError(t, err)
	desc := val.(*Desc)
	_, present := desc.Ingesters["instance-1"]
	assert.False(t, present, "forget must remove the named instance when enabled")
}

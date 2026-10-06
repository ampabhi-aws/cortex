package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBoundedProfiler_RejectsSecondsOverCap(t *testing.T) {
	called := false
	h := boundedProfiler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	for _, s := range []string{strconv.Itoa(maxProfilingSeconds + 1), "0", "-1", "notanint", "2147483647"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/debug/fgprof?seconds="+s, nil)
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, "seconds=%q should be rejected", s)
	}
	require.False(t, called, "inner handler must not run for invalid seconds")
}

func TestBoundedProfiler_AcceptsValidSeconds(t *testing.T) {
	called := false
	h := boundedProfiler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	for _, s := range []string{"", "1", strconv.Itoa(maxProfilingSeconds)} {
		called = false
		rec := httptest.NewRecorder()
		url := "/debug/fgprof"
		if s != "" {
			url += "?seconds=" + s
		}
		req := httptest.NewRequest("GET", url, nil)
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, "seconds=%q should be accepted", s)
		require.True(t, called, "inner handler must run for seconds=%q", s)
	}
}

func TestBoundedProfiler_SerialisesConcurrentRequests(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	h := boundedProfiler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
	}))

	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/debug/fgprof?seconds=1", nil)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.ServeHTTP(rec1, req1)
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first request never entered inner handler")
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/debug/fgprof?seconds=1", nil)
	h.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusTooManyRequests, rec2.Code)

	close(release)
	wg.Wait()
	require.Equal(t, http.StatusOK, rec1.Code)
}

package authz

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// countingPDP records call counts and batch sizes so tests can prove caching behavior. It
// deliberately does NOT implement Healther.
type countingPDP struct {
	evalCalls  int
	batchCalls int
	batchSizes []int
	allow      map[string]bool // keyed by action
	err        error
}

func (f *countingPDP) Evaluate(_ context.Context, _ Subject, action string, _ Resource, _ map[string]any) (Decision, error) {
	f.evalCalls++
	if f.err != nil {
		return Decision{}, f.err
	}
	return Decision{Allow: f.allow[action]}, nil
}

func (f *countingPDP) Evaluations(_ context.Context, reqs []EvalRequest) ([]Decision, error) {
	f.batchCalls++
	f.batchSizes = append(f.batchSizes, len(reqs))
	if f.err != nil {
		return nil, f.err
	}
	out := make([]Decision, len(reqs))
	for i, r := range reqs {
		out[i] = Decision{Allow: f.allow[r.Action]}
	}
	return out, nil
}

// healthyCountingPDP adds Healther so we can test forwarding through the cache.
type healthyCountingPDP struct {
	countingPDP
	healthErr error
}

func (f *healthyCountingPDP) Health(context.Context) error { return f.healthErr }

func TestCacheEvaluateHitsAvoidInnerCall(t *testing.T) {
	inner := &countingPDP{allow: map[string]bool{"read": true}}
	c := newCachingPDP(inner, time.Minute, nil)

	for i := 0; i < 3; i++ {
		dec, err := c.Evaluate(context.Background(), Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence", ID: "1"}, nil)
		if err != nil || !dec.Allow {
			t.Fatalf("Evaluate #%d = (%+v, %v), want allow", i, dec, err)
		}
	}
	if inner.evalCalls != 1 {
		t.Errorf("inner Evaluate calls = %d, want 1 (cached)", inner.evalCalls)
	}
}

func TestCacheKeyVariesByTuple(t *testing.T) {
	inner := &countingPDP{allow: map[string]bool{"read": true, "delete": true}}
	c := newCachingPDP(inner, time.Minute, nil)
	ctx := context.Background()
	// Different action, different resource id, and different subject must all miss.
	_, _ = c.Evaluate(ctx, Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence", ID: "1"}, nil)
	_, _ = c.Evaluate(ctx, Subject{Type: "user", ID: "a"}, "delete", Resource{Type: "evidence", ID: "1"}, nil)
	_, _ = c.Evaluate(ctx, Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence", ID: "2"}, nil)
	_, _ = c.Evaluate(ctx, Subject{Type: "user", ID: "b"}, "read", Resource{Type: "evidence", ID: "1"}, nil)
	if inner.evalCalls != 4 {
		t.Errorf("inner Evaluate calls = %d, want 4 (distinct tuples)", inner.evalCalls)
	}
}

func TestCacheExpiry(t *testing.T) {
	inner := &countingPDP{allow: map[string]bool{"read": true}}
	c := newCachingPDP(inner, time.Millisecond, nil)
	ctx := context.Background()
	if _, err := c.Evaluate(ctx, Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence"}, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // well past the 1ms TTL
	if _, err := c.Evaluate(ctx, Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence"}, nil); err != nil {
		t.Fatal(err)
	}
	if inner.evalCalls != 2 {
		t.Errorf("inner Evaluate calls = %d, want 2 (entry expired)", inner.evalCalls)
	}
}

func TestCacheDoesNotCacheErrors(t *testing.T) {
	inner := &countingPDP{err: errors.New("boom")}
	c := newCachingPDP(inner, time.Minute, nil)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := c.Evaluate(ctx, Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence"}, nil); err == nil {
			t.Fatal("Evaluate error = nil, want error")
		}
	}
	if inner.evalCalls != 2 {
		t.Errorf("inner Evaluate calls = %d, want 2 (errors not cached)", inner.evalCalls)
	}
}

// TestCacheBatchPartialMiss is the key batch property: cached entries are served locally,
// and only the misses go to the inner PDP in a single batched call.
func TestCacheBatchPartialMiss(t *testing.T) {
	inner := &countingPDP{allow: map[string]bool{"read": true, "delete": false, "create": true}}
	c := newCachingPDP(inner, time.Minute, nil)
	ctx := context.Background()

	// Prime "read" via a single Evaluate.
	if _, err := c.Evaluate(ctx, Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence"}, nil); err != nil {
		t.Fatal(err)
	}

	reqs := []EvalRequest{
		{Subject: Subject{Type: "user", ID: "a"}, Action: "read", Resource: Resource{Type: "evidence"}},   // cached hit
		{Subject: Subject{Type: "user", ID: "a"}, Action: "delete", Resource: Resource{Type: "evidence"}}, // miss
		{Subject: Subject{Type: "user", ID: "a"}, Action: "create", Resource: Resource{Type: "evidence"}}, // miss
	}
	decs, err := c.Evaluations(ctx, reqs)
	if err != nil {
		t.Fatalf("Evaluations error = %v", err)
	}
	want := []bool{true, false, true}
	for i, w := range want {
		if decs[i].Allow != w {
			t.Errorf("decisions[%d].Allow = %v, want %v", i, decs[i].Allow, w)
		}
	}
	if inner.batchCalls != 1 {
		t.Fatalf("inner batch calls = %d, want 1", inner.batchCalls)
	}
	if got := inner.batchSizes[0]; got != 2 {
		t.Errorf("batched %d requests, want 2 (only the misses)", got)
	}

	// A second identical batch is fully served from cache: no new inner call.
	if _, err := c.Evaluations(ctx, reqs); err != nil {
		t.Fatal(err)
	}
	if inner.batchCalls != 1 {
		t.Errorf("inner batch calls after warm cache = %d, want 1", inner.batchCalls)
	}
}

// TestCacheEvictsExpiredAtCap proves the soft cap: once the map is full, putting a fresh
// entry sweeps the expired ones instead of growing without bound.
func TestCacheEvictsExpiredAtCap(t *testing.T) {
	inner := &countingPDP{allow: map[string]bool{}}
	c := newCachingPDP(inner, time.Minute, nil).(*cachingPDP)

	now := time.Now()
	// Fill to the cap with already-expired entries (expires in the past).
	for i := 0; i < maxCacheEntries; i++ {
		c.entries[fmt.Sprintf("stale-%d", i)] = cacheEntry{expires: now.Add(-time.Hour)}
	}
	if len(c.entries) != maxCacheEntries {
		t.Fatalf("preloaded %d entries, want %d", len(c.entries), maxCacheEntries)
	}
	// One put at the cap should sweep the expired entries before inserting.
	c.put("fresh", Decision{Allow: true}, now)
	if len(c.entries) != 1 {
		t.Errorf("entries after sweep = %d, want 1 (all stale evicted, one fresh)", len(c.entries))
	}
}

func TestCacheHealthForwarding(t *testing.T) {
	// Inner without Healther: cache reports healthy.
	plain := newCachingPDP(&countingPDP{}, time.Minute, nil)
	if err := plain.(Healther).Health(context.Background()); err != nil {
		t.Errorf("Health with non-Healther inner = %v, want nil", err)
	}
	// Inner with Healther: cache forwards the result.
	sentinel := errors.New("pdp down")
	withHealth := newCachingPDP(&healthyCountingPDP{healthErr: sentinel}, time.Minute, nil)
	if err := withHealth.(Healther).Health(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("Health forwarding = %v, want %v", err, sentinel)
	}
}

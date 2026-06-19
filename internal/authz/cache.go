package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// cachingPDP is a short-TTL decision cache wrapping any PDP, used to absorb the network
// hop of remote drivers (design §6). It caches only successful decisions; errors and
// unavailability are never cached. Safe for concurrent use.
type cachingPDP struct {
	inner  PDP
	ttl    time.Duration
	logger *zap.SugaredLogger

	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	decision Decision
	expires  time.Time
}

// maxCacheEntries bounds the cache so a long-running process with high-cardinality
// (subject, resource) tuples can't grow it without limit. When the map reaches this size a
// put first sweeps expired entries; given the short TTL this is normally enough to keep it
// well under the cap (it's a soft cap, not a hard reservoir, so no LRU bookkeeping).
const maxCacheEntries = 4096

func newCachingPDP(inner PDP, ttl time.Duration, logger *zap.SugaredLogger) PDP {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &cachingPDP{
		inner:   inner,
		ttl:     ttl,
		logger:  logger,
		entries: make(map[string]cacheEntry),
	}
}

// cacheKey hashes the full decision tuple so anything that could change the decision —
// subject (incl. props), action, resource (incl. props), and context — changes the key.
// An unmarshalable tuple yields "" meaning "do not cache".
func cacheKey(s Subject, action string, r Resource, reqCtx map[string]any) string {
	payload := struct {
		S Subject        `json:"s"`
		A string         `json:"a"`
		R Resource       `json:"r"`
		C map[string]any `json:"c"`
	}{s, action, r, reqCtx}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (c *cachingPDP) get(key string, now time.Time) (Decision, bool) {
	if key == "" {
		return Decision{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return Decision{}, false
	}
	if now.After(e.expires) {
		delete(c.entries, key)
		return Decision{}, false
	}
	return e.decision, true
}

func (c *cachingPDP) put(key string, d Decision, now time.Time) {
	if key == "" {
		return
	}
	c.mu.Lock()
	// Opportunistic eviction: only when we're at the cap, and only entries already past
	// their TTL — bounded, cheap, and never drops a live decision.
	if len(c.entries) >= maxCacheEntries {
		for k, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, k)
			}
		}
	}
	c.entries[key] = cacheEntry{decision: d, expires: now.Add(c.ttl)}
	c.mu.Unlock()
}

// Evaluate serves from cache when fresh, otherwise delegates and caches the result.
func (c *cachingPDP) Evaluate(ctx context.Context, s Subject, action string, r Resource, reqCtx map[string]any) (Decision, error) {
	key := cacheKey(s, action, r, reqCtx)
	if d, ok := c.get(key, time.Now()); ok {
		return d, nil
	}
	d, err := c.inner.Evaluate(ctx, s, action, r, reqCtx)
	if err != nil {
		return d, err
	}
	c.put(key, d, time.Now())
	return d, nil
}

// Evaluations serves cached entries directly and batches only the misses into a single
// inner call, preserving the "one batched call" benefit while still caching.
func (c *cachingPDP) Evaluations(ctx context.Context, reqs []EvalRequest) ([]Decision, error) {
	now := time.Now()
	out := make([]Decision, len(reqs))
	keys := make([]string, len(reqs))
	var missIdx []int
	var missReqs []EvalRequest
	for i, req := range reqs {
		key := cacheKey(req.Subject, req.Action, req.Resource, req.Context)
		keys[i] = key
		if d, ok := c.get(key, now); ok {
			out[i] = d
			continue
		}
		missIdx = append(missIdx, i)
		missReqs = append(missReqs, req)
	}
	if len(missReqs) == 0 {
		return out, nil
	}
	decisions, err := c.inner.Evaluations(ctx, missReqs)
	if err != nil {
		return nil, err
	}
	if len(decisions) != len(missReqs) {
		return nil, fmt.Errorf("authz: cache: inner returned %d decisions for %d requests", len(decisions), len(missReqs))
	}
	now = time.Now()
	for j, idx := range missIdx {
		out[idx] = decisions[j]
		c.put(keys[idx], decisions[j], now)
	}
	return out, nil
}

// Health forwards to the inner PDP when it supports it, so wrapping in a cache doesn't
// hide the remote PDP's health from the readiness check.
func (c *cachingPDP) Health(ctx context.Context) error {
	if h, ok := c.inner.(Healther); ok {
		return h.Health(ctx)
	}
	return nil
}

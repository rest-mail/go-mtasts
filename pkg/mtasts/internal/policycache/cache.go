package policycache

import (
	"sync"
	"time"

	"github.com/rest-mail/go-mtasts/pkg/mtasts/internal/policygrammar"
)

// maxCacheTTL caps how long a policy is cached regardless of its max_age
// (RFC 8461 §3.2 allows up to 31557600s / ~1 year).
const maxCacheTTL = policygrammar.MaxAgeLimit * time.Second

// refreshInterval is how long a cached policy is served before Resolve fetches
// it again even though its id is unchanged. RFC 8461 §3.3 says to refresh
// cached policies before they expire and suggests once per day; §10.2 explains
// why: an attacker who blocks the refresh must then do so for the policy's
// whole max_age, not just at the moment it runs out.
const refreshInterval = 24 * time.Hour

// defaultNegativeTTL bounds how often a failed policy fetch/parse for a given
// version id is retried. RFC 8461 §3.3 recommends limiting retries to no more
// than about once per five minutes per version id, so a domain whose policy
// host is down or being blocked is not re-probed on every outbound message.
const defaultNegativeTTL = 5 * time.Minute

// sweepInterval is how often a store also removes every expired entry. An
// entry found expired by a lookup is removed then; the sweep covers domains
// that are never looked up again, so the cache holds only entries still in
// force, not one per domain ever seen.
const sweepInterval = defaultNegativeTTL

// Cache holds successful policies and failed discoveries, keyed by domain.
// Its zero value is ready for concurrent use; a policy's contents are owned by
// the caller, just as they are at the Resolver boundary.
//
// An entry is removed once it can no longer be used: a policy when its max_age
// runs out, a failure when its retry window closes. A lookup that finds its
// entry expired removes it, and a store sweeps out every expired entry at most
// once per sweepInterval, so memory follows the policies in force rather than
// every domain ever resolved.
type Cache[P any] struct {
	mu        sync.Mutex
	cache     map[string]cacheEntry[P]
	negCache  map[string]negEntry
	lastSweep time.Time
}

type cacheEntry[P any] struct {
	policy    *P
	id        string
	fetchedAt time.Time
	expiresAt time.Time
}

// negEntry records that discovery of policy id for a domain failed (fetch or
// parse), and why, and must not be retried until expiresAt. The id scopes the
// suppression per RFC 8461 §3.3: a freshly published id is a new policy and is
// fetched immediately rather than served from a stale failure.
type negEntry struct {
	id        string
	err       error
	expiresAt time.Time
}

// Cached returns the cached policy for domain only when it is non-expired, its
// id matches the freshly discovered id, and it is not yet due for its daily
// refresh. This is the fast path that lets Resolve skip the HTTPS fetch while
// the published id is unchanged.
func (r *Cache[P]) Cached(domain, id string, now time.Time) *P {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, found := r.live(domain, now)
	if found && e.id == id && now.Sub(e.fetchedAt) < refreshInterval {
		return e.policy
	}
	return nil
}

// Fallback returns a non-expired policy regardless of its discovered id.
func (r *Cache[P]) Fallback(domain string, now time.Time) *P {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, found := r.live(domain, now); found {
		return e.policy
	}
	return nil
}

// live returns domain's cached policy if it has not expired, and removes it
// if it has. The caller holds r.mu.
func (r *Cache[P]) live(domain string, now time.Time) (cacheEntry[P], bool) {
	e, found := r.cache[domain]
	if found && !now.Before(e.expiresAt) {
		delete(r.cache, domain)
		return cacheEntry[P]{}, false
	}
	return e, found
}

// RecentlyFailed reports whether a fetch/parse for domain's current id failed
// within the negative-cache TTL, and why. It is scoped to the id so that a rotated
// (newly published) id is never suppressed by the previous id's failure.
func (r *Cache[P]) RecentlyFailed(domain, id string, now time.Time) (error, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, found := r.negCache[domain]
	if !found {
		return nil, false
	}
	if !now.Before(e.expiresAt) {
		delete(r.negCache, domain)
		return nil, false
	}
	if e.id == id {
		return e.err, true
	}
	return nil, false
}

// StoreFailure records that discovery of id for domain failed, and why,
// suppressing re-fetch of the same id until now plus the floored retry TTL.
func (r *Cache[P]) StoreFailure(domain, id string, now time.Time, failure error, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweep(now)
	if r.negCache == nil {
		r.negCache = make(map[string]negEntry)
	}
	r.negCache[domain] = negEntry{id: id, err: failure, expiresAt: now.Add(negativeTTL(ttl))}
}

// negativeTTL floors retry suppression at five minutes per policy version.
func negativeTTL(ttl time.Duration) time.Duration {
	if ttl > defaultNegativeTTL {
		return ttl
	}
	return defaultNegativeTTL
}

// Store caches policy for its bounded lifetime and clears any prior failure. A
// policy with no lifetime (max_age 0) replaces any cached one but is not kept.
func (r *Cache[P]) Store(domain, id string, policy *P, seconds int, now time.Time) {
	// policygrammar.Parse already bounds max_age to 0..policygrammar.MaxMaxAge, but a directly
	// constructed policy could carry an out-of-range value. Clamp the seconds
	// before the Duration multiplication so it can neither wrap to a negative TTL
	// (immediate expiry -> re-fetch every message) nor exceed the cache cap.
	switch {
	case seconds < 0:
		seconds = 0
	case seconds > policygrammar.MaxAgeLimit:
		seconds = policygrammar.MaxAgeLimit
	}
	ttl := time.Duration(seconds) * time.Second
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweep(now)
	// A successful fetch clears any prior negative entry so a subsequent failure
	// starts a fresh suppression window rather than inheriting a stale one.
	delete(r.negCache, domain)
	if ttl <= 0 {
		delete(r.cache, domain)
		return
	}
	if r.cache == nil {
		r.cache = make(map[string]cacheEntry[P])
	}
	r.cache[domain] = cacheEntry[P]{policy: policy, id: id, fetchedAt: now, expiresAt: now.Add(ttl)}
}

// sweep removes every expired policy and failure, at most once per
// sweepInterval. After a clock moves backwards, the next sweep waits until
// the clock is sweepInterval past the last one. The caller holds r.mu.
func (r *Cache[P]) sweep(now time.Time) {
	if !r.lastSweep.IsZero() && now.Sub(r.lastSweep) < sweepInterval {
		return
	}
	r.lastSweep = now
	for domain, e := range r.cache {
		if !now.Before(e.expiresAt) {
			delete(r.cache, domain)
		}
	}
	for domain, e := range r.negCache {
		if !now.Before(e.expiresAt) {
			delete(r.negCache, domain)
		}
	}
}

// Len returns the number of cached policies and of remembered failures,
// expired ones included until they are removed.
func (r *Cache[P]) Len() (policies, failures int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cache), len(r.negCache)
}

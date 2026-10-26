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

// Cache holds successful policies and failed discoveries, keyed by domain.
// Its zero value is ready for concurrent use; a policy's contents are owned by
// the caller, just as they are at the Resolver boundary.
type Cache[P any] struct {
	mu       sync.Mutex
	cache    map[string]cacheEntry[P]
	negCache map[string]negEntry
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
	if e, found := r.cache[domain]; found && e.id == id && now.Before(e.expiresAt) && now.Sub(e.fetchedAt) < refreshInterval {
		return e.policy
	}
	return nil
}

// Fallback returns a non-expired policy regardless of its discovered id.
func (r *Cache[P]) Fallback(domain string, now time.Time) *P {
	r.mu.Lock()
	e, found := r.cache[domain]
	r.mu.Unlock()
	if !found || !now.Before(e.expiresAt) {
		return nil
	}
	return e.policy
}

// RecentlyFailed reports whether a fetch/parse for domain's current id failed
// within the negative-cache TTL, and why. It is scoped to the id so that a rotated
// (newly published) id is never suppressed by the previous id's failure.
func (r *Cache[P]) RecentlyFailed(domain, id string, now time.Time) (error, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, found := r.negCache[domain]
	if found && e.id == id && now.Before(e.expiresAt) {
		return e.err, true
	}
	return nil, false
}

// StoreFailure records that discovery of id for domain failed, and why,
// suppressing re-fetch of the same id until now plus the floored retry TTL.
func (r *Cache[P]) StoreFailure(domain, id string, now time.Time, failure error, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
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

// Store caches policy for its bounded lifetime and clears any prior failure.
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
	if r.cache == nil {
		r.cache = make(map[string]cacheEntry[P])
	}
	r.cache[domain] = cacheEntry[P]{policy: policy, id: id, fetchedAt: now, expiresAt: now.Add(ttl)}
	// A successful fetch clears any prior negative entry so a subsequent failure
	// starts a fresh suppression window rather than inheriting a stale one.
	delete(r.negCache, domain)
}

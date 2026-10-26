package mtasts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rest-mail/go-mtasts/pkg/mtasts/internal/txtrecord"
)

// ErrNoPolicy is returned by Resolver.Resolve when the domain publishes no
// usable MTA-STS policy. It signals the caller to fall back to ordinary
// opportunistic-TLS behaviour (fail-open, per RFC 8461 section 5).
//
// The error Resolve returns wraps ErrNoPolicy, and with it the reason when
// discovery found one: ErrNoRecord, ErrPolicyFetch or ErrPolicyInvalid, or a
// DNS error. errors.Is tells them apart, which is what a TLS-RPT report needs
// (RFC 8460 §4.3.2.2): a domain without a record does not use MTA-STS, while
// one whose policy could not be fetched or read is a failure to report.
var ErrNoPolicy = errors.New("mtasts: no policy")

// The reasons Resolve finds no policy, each wrapped in ErrNoPolicy.
var (
	// ErrNoRecord: the domain publishes no valid _mta-sts TXT record, so it
	// does not use MTA-STS (RFC 8461 §3.1).
	ErrNoRecord = errors.New("mtasts: no valid _mta-sts TXT record")
	// ErrPolicyFetch: the domain publishes a record, but its policy could not
	// be fetched over HTTPS (RFC 8461 §3.3); the error also wraps the fetch's
	// own, a certificate the fetch could not verify among them (RFC 8460's
	// sts-policy-fetch-error, or sts-webpki-invalid).
	ErrPolicyFetch = errors.New("mtasts: the policy could not be fetched")
	// ErrPolicyInvalid: the policy was fetched but is not a valid policy
	// (RFC 8461 §3.2; RFC 8460's sts-policy-invalid).
	ErrPolicyInvalid = errors.New("mtasts: the policy is not valid")
)

// maxCacheTTL caps how long a policy is cached regardless of its max_age
// (RFC 8461 §3.2 allows up to 31557600s / ~1 year).
const maxCacheTTL = maxMaxAge * time.Second

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

// LookupTXTFunc resolves TXT records for a name. Injectable for testing.
type LookupTXTFunc func(ctx context.Context, name string) ([]string, error)

// FetchPolicyFunc fetches the raw policy file at the given HTTPS URL.
// Injectable for testing.
type FetchPolicyFunc func(ctx context.Context, url string) ([]byte, error)

// Resolver discovers and caches MTA-STS policies. The DNS and HTTP fetch steps
// are injectable so the resolver can be unit-tested without network access.
type Resolver struct {
	// LookupTXT resolves the _mta-sts.<domain> TXT record. Defaults to
	// net.DefaultResolver.LookupTXT.
	LookupTXT LookupTXTFunc
	// FetchPolicy fetches the policy file over HTTPS. Defaults to a verified
	// HTTPS GET that does not follow redirects.
	FetchPolicy FetchPolicyFunc
	// Now returns the current time; overridable in tests. Defaults to time.Now.
	Now func() time.Time

	// NegativeTTL is how long a failed policy fetch/parse for a given version id
	// is remembered so repeated Resolve calls within the window do not re-probe a
	// broken or blocked policy host (RFC 8461 §3.3). Zero uses defaultNegativeTTL
	// (5 minutes); a value below that floor is raised to it, since a shorter
	// interval would reopen the re-probe amplifier the negative cache exists to
	// close.
	NegativeTTL time.Duration

	// RefreshFailed, if set, is called when live discovery fails while a
	// non-expired policy is cached, so Resolve serves the cached policy: the
	// TXT lookup errors or finds no valid record, or the policy fetch or parse
	// fails. It is not called when the cached policy's mode is "none". RFC 8461
	// §3.3 and §10.2 ask MTAs to alert administrators to such failures long
	// before the cached policy expires; use it to log them. It runs in Resolve's
	// goroutine.
	RefreshFailed func(domain string, cached *Policy, err error)

	mu       sync.Mutex
	cache    map[string]cacheEntry
	negCache map[string]negEntry
}

type cacheEntry struct {
	policy    *Policy
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

// NewResolver returns a Resolver wired to the real network. Callers may replace
// LookupTXT / FetchPolicy / Now afterwards (e.g. to plumb an insecure fetch for
// a dev deployment, or to inject fakes in tests).
func NewResolver() *Resolver {
	return &Resolver{
		LookupTXT:   net.DefaultResolver.LookupTXT,
		FetchPolicy: func(ctx context.Context, url string) ([]byte, error) { return HTTPFetch(ctx, url, false) },
		Now:         time.Now,
		cache:       make(map[string]cacheEntry),
		negCache:    make(map[string]negEntry),
	}
}

// TXTName returns the DNS name that carries a domain's MTA-STS policy id.
func TXTName(domain string) string { return "_mta-sts." + normalizeHost(domain) }

// PolicyURL returns the HTTPS URL of a domain's policy file.
func PolicyURL(domain string) string {
	return "https://mta-sts." + normalizeHost(domain) + "/.well-known/mta-sts.txt"
}

// Resolve returns the MTA-STS policy for domain, or ErrNoPolicy if none is
// usable. It reads the _mta-sts.<domain> TXT record for the policy id, serves a
// cached policy while its max_age has not elapsed and the id is unchanged, and
// otherwise fetches and parses the HTTPS policy file. A cached policy fetched
// more than a day ago is fetched again even when its id is unchanged, so it is
// refreshed long before it expires (RFC 8461 §3.3). domain is the Policy
// Domain itself: Resolve never looks at a parent zone (RFC 8461 §3.4).
//
// A valid, non-expired cached policy is never dropped by a transient discovery
// failure. When the TXT lookup errors, carries no usable id, or the HTTPS
// re-fetch fails or returns an unparseable body, Resolve serves the cached
// policy (regardless of its id) until its max_age legitimately elapses. This
// upholds RFC 8461 sections 3.1 and 3.3 — "the absence of a usable TXT record
// is not by itself sufficient to remove a sender's previously cached policy",
// and a valid cached policy MUST be applied when no live policy can be
// discovered — and defeats the section 10.2 downgrade attack in which an
// on-path adversary strips MTA-STS by merely blocking the TXT response or the
// policy fetch.
//
// Fail-open (RFC 8461 section 5) only when no non-expired policy is cached: a
// missing/invalid TXT record, a fetch error, or an unparseable policy then
// yield ErrNoPolicy so the caller reverts to opportunistic TLS rather than
// blocking mail.
//
// A fetch or parse failure for a discovered id is negative-cached for
// NegativeTTL (default 5 minutes). While that entry is live, a later Resolve
// that discovers the same id skips the HTTPS fetch and falls straight through to
// the cached-or-fail-open path, so a domain whose policy host is down or being
// blocked is not re-probed on every outbound message (RFC 8461 §3.3). The
// suppression is scoped to the id: a newly published id is fetched immediately.
func (r *Resolver) Resolve(ctx context.Context, domain string) (*Policy, error) {
	domain = normalizeHost(domain)
	// A recipient domain that is not a DNS name (empty, or holding "/", "@" or
	// ":") has no policy, and must not be spliced into the policy URL, where it
	// could name a different host, port or path.
	if !validDomain(domain) {
		return nil, ErrNoPolicy
	}

	txts, err := r.lookupTXT(ctx, TXTName(domain))
	// DNS and HTTPS can outlast a cached policy. Judge its validity after
	// each blocking operation, not at the start of this Resolve call.
	now := r.now()
	if err != nil {
		// A name that does not exist publishes no record; another DNS
		// failure says nothing either way.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			err = fmt.Errorf("%w: %w", ErrNoRecord, err)
		}
		return r.cachedOrNoPolicy(domain, now, err, true)
	}
	id, ok := txtrecord.ID(txts)
	if !ok {
		return r.cachedOrNoPolicy(domain, now, ErrNoRecord, true)
	}

	if p := r.cached(domain, id, now); p != nil {
		return p, nil
	}

	// Rate-limit re-probing of a policy host that recently failed for this same
	// id: serve any still-valid cached policy or fail open without a fresh fetch.
	if failure, ok := r.recentlyFailed(domain, id, now); ok {
		return r.cachedOrNoPolicy(domain, now, failure, false)
	}

	body, err := r.fetchPolicy(ctx, PolicyURL(domain))
	now = r.now()
	if err != nil {
		failure := fmt.Errorf("%w: %w", ErrPolicyFetch, err)
		r.storeFailure(domain, id, now, failure)
		return r.cachedOrNoPolicy(domain, now, failure, true)
	}
	policy, err := ParsePolicy(body)
	now = r.now()
	if err != nil {
		failure := fmt.Errorf("%w: %w", ErrPolicyInvalid, err)
		r.storeFailure(domain, id, now, failure)
		return r.cachedOrNoPolicy(domain, now, failure, true)
	}

	r.store(domain, id, policy, now)
	return policy, nil
}

// cached returns the cached policy for domain only when it is non-expired, its
// id matches the freshly discovered id, and it is not yet due for its daily
// refresh. This is the fast path that lets Resolve skip the HTTPS fetch while
// the published id is unchanged.
func (r *Resolver) cached(domain, id string, now time.Time) *Policy {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, found := r.cache[domain]; found && e.id == id && now.Before(e.expiresAt) && now.Sub(e.fetchedAt) < refreshInterval {
		return e.policy
	}
	return nil
}

// cachedOrNoPolicy is the fallback taken when live discovery fails. It serves
// any non-expired cached policy regardless of its id — the id governs whether
// to re-fetch, not whether the cached policy is still valid — and returns
// ErrNoPolicy only when nothing usable remains in the cache (RFC 8461 §3.1,
// §3.3). failure is why discovery failed, which the ErrNoPolicy returned
// wraps; attempted is false when no attempt was made this time (a
// negative-cached id). A cached policy served after a failed attempt is
// reported to RefreshFailed unless its mode is "none".
func (r *Resolver) cachedOrNoPolicy(domain string, now time.Time, failure error, attempted bool) (*Policy, error) {
	r.mu.Lock()
	e, found := r.cache[domain]
	r.mu.Unlock()
	if !found || !now.Before(e.expiresAt) {
		if failure == nil {
			return nil, ErrNoPolicy
		}
		return nil, fmt.Errorf("%w: %w", ErrNoPolicy, failure)
	}
	if attempted && failure != nil && r.RefreshFailed != nil && e.policy.Mode != ModeNone {
		r.RefreshFailed(domain, e.policy, failure)
	}
	return e.policy, nil
}

// recentlyFailed reports whether a fetch/parse for domain's current id failed
// within the negative-cache TTL, and why. It is scoped to the id so that a rotated
// (newly published) id is never suppressed by the previous id's failure.
func (r *Resolver) recentlyFailed(domain, id string, now time.Time) (error, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, found := r.negCache[domain]
	if found && e.id == id && now.Before(e.expiresAt) {
		return e.err, true
	}
	return nil, false
}

// storeFailure records that discovery of id for domain failed, and why,
// suppressing re-fetch of the same id until now+negTTL.
func (r *Resolver) storeFailure(domain, id string, now time.Time, failure error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.negCache == nil {
		r.negCache = make(map[string]negEntry)
	}
	r.negCache[domain] = negEntry{id: id, err: failure, expiresAt: now.Add(r.negTTL())}
}

// negTTL is the negative-cache lifetime: NegativeTTL when it exceeds the default
// floor, otherwise defaultNegativeTTL. Flooring keeps a misconfigured
// sub-default (or zero) value from reopening the per-message re-probe amplifier.
func (r *Resolver) negTTL() time.Duration {
	if r.NegativeTTL > defaultNegativeTTL {
		return r.NegativeTTL
	}
	return defaultNegativeTTL
}

func (r *Resolver) store(domain, id string, policy *Policy, now time.Time) {
	// ParsePolicy already bounds max_age to 0..maxMaxAge, but a directly
	// constructed Policy could carry an out-of-range value. Clamp the seconds
	// before the Duration multiplication so it can neither wrap to a negative TTL
	// (immediate expiry -> re-fetch every message) nor exceed the cache cap.
	seconds := policy.MaxAge
	switch {
	case seconds < 0:
		seconds = 0
	case seconds > maxMaxAge:
		seconds = maxMaxAge
	}
	ttl := time.Duration(seconds) * time.Second
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		r.cache = make(map[string]cacheEntry)
	}
	r.cache[domain] = cacheEntry{policy: policy, id: id, fetchedAt: now, expiresAt: now.Add(ttl)}
	// A successful fetch clears any prior negative entry so a subsequent failure
	// starts a fresh suppression window rather than inheriting a stale one.
	delete(r.negCache, domain)
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// lookupTXT resolves the policy-id TXT record, defaulting to
// net.DefaultResolver.LookupTXT when the field is unset. Mirroring now(), this
// lets a zero-value Resolver (mtasts.Resolver{}, not NewResolver) be used
// without a nil-func panic.
func (r *Resolver) lookupTXT(ctx context.Context, name string) ([]string, error) {
	if r.LookupTXT != nil {
		return r.LookupTXT(ctx, name)
	}
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// fetchPolicy fetches the policy file, defaulting to a verified HTTPS GET
// (HTTPFetch with insecure=false, matching NewResolver) when the field is
// unset, so a zero-value Resolver does not nil-panic on the fetch step.
func (r *Resolver) fetchPolicy(ctx context.Context, url string) ([]byte, error) {
	if r.FetchPolicy != nil {
		return r.FetchPolicy(ctx, url)
	}
	return HTTPFetch(ctx, url, false)
}

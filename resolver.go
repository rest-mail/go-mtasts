package mtasts

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrNoPolicy is returned by Resolver.Resolve when the domain publishes no
// usable MTA-STS policy. It signals the caller to fall back to ordinary
// opportunistic-TLS behaviour (fail-open, per RFC 8461 section 5).
var ErrNoPolicy = errors.New("mtasts: no policy")

// maxPolicyBody bounds the policy file read to guard against abuse.
const maxPolicyBody = 64 << 10

// maxCacheTTL caps how long a policy is cached regardless of its max_age
// (RFC 8461 allows up to 31557600s / ~1 year).
const maxCacheTTL = 31557600 * time.Second

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

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	policy    *Policy
	id        string
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
// otherwise fetches and parses the HTTPS policy file.
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
func (r *Resolver) Resolve(ctx context.Context, domain string) (*Policy, error) {
	domain = normalizeHost(domain)
	if domain == "" {
		return nil, ErrNoPolicy
	}

	now := r.now()

	txts, err := r.LookupTXT(ctx, TXTName(domain))
	if err != nil {
		return r.cachedOrNoPolicy(domain, now)
	}
	id, ok := parseTXTID(txts)
	if !ok {
		return r.cachedOrNoPolicy(domain, now)
	}

	if p := r.cached(domain, id, now); p != nil {
		return p, nil
	}

	body, err := r.FetchPolicy(ctx, PolicyURL(domain))
	if err != nil {
		return r.cachedOrNoPolicy(domain, now)
	}
	policy, err := ParsePolicy(body)
	if err != nil {
		return r.cachedOrNoPolicy(domain, now)
	}

	r.store(domain, id, policy, now)
	return policy, nil
}

// cached returns the cached policy for domain only when it is non-expired and
// its id matches the freshly discovered id. This is the fast path that lets
// Resolve skip the HTTPS fetch while the published id is unchanged.
func (r *Resolver) cached(domain, id string, now time.Time) *Policy {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, found := r.cache[domain]; found && e.id == id && now.Before(e.expiresAt) {
		return e.policy
	}
	return nil
}

// cachedOrNoPolicy is the fallback taken when live discovery fails. It serves
// any non-expired cached policy regardless of its id — the id governs whether
// to re-fetch, not whether the cached policy is still valid — and returns
// ErrNoPolicy only when nothing usable remains in the cache (RFC 8461 §3.1,
// §3.3).
func (r *Resolver) cachedOrNoPolicy(domain string, now time.Time) (*Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, found := r.cache[domain]; found && now.Before(e.expiresAt) {
		return e.policy, nil
	}
	return nil, ErrNoPolicy
}

func (r *Resolver) store(domain, id string, policy *Policy, now time.Time) {
	ttl := time.Duration(policy.MaxAge) * time.Second
	if ttl > maxCacheTTL {
		ttl = maxCacheTTL
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		r.cache = make(map[string]cacheEntry)
	}
	r.cache[domain] = cacheEntry{policy: policy, id: id, expiresAt: now.Add(ttl)}
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// parseTXTID extracts the policy id from the _mta-sts.<domain> TXT records.
// Exactly one record must begin with "v=STSv1" and carry a non-empty id
// (RFC 8461 section 3.1); anything else is treated as "no policy".
func parseTXTID(records []string) (string, bool) {
	found := 0
	id := ""
	for _, rec := range records {
		var v, thisID string
		for _, field := range strings.Split(rec, ";") {
			k, val, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			switch strings.TrimSpace(k) {
			case "v":
				v = strings.TrimSpace(val)
			case "id":
				thisID = strings.TrimSpace(val)
			}
		}
		if v == Version {
			found++
			id = thisID
		}
	}
	if found != 1 || id == "" {
		return "", false
	}
	return id, true
}

// HTTPFetch performs the HTTPS GET for a policy file. Per RFC 8461 section 3.3
// the policy MUST be fetched over HTTPS with a verified server certificate, and
// redirects MUST NOT be followed:
//
//   - The URL scheme is pinned to https. A non-https scheme is rejected so a
//     direct caller cannot fetch a policy over cleartext; only when insecure is
//     explicitly set (a dev/test deployment) is a plaintext http URL permitted.
//   - The server certificate for mta-sts.<domain> is verified unless insecure
//     is set.
//   - 3xx redirects are not followed, which also prevents a redirect from
//     downgrading the fetch to http or steering it to a different host — either
//     of which would defeat the policy origin.
//
// A plaintext, invalid-certificate, or redirected fetch therefore fails rather
// than returning a policy.
func HTTPFetch(ctx context.Context, url string, insecure bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	switch req.URL.Scheme {
	case "https":
		// Verified HTTPS: the required transport for a policy fetch.
	case "http":
		if !insecure {
			return nil, fmt.Errorf("mtasts: refusing to fetch policy over cleartext http (RFC 8461 requires https): %s", url)
		}
	default:
		return nil, fmt.Errorf("mtasts: unsupported policy URL scheme %q (RFC 8461 requires https)", req.URL.Scheme)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure, //nolint:gosec // gated by caller; enforce path always passes false
				MinVersion:         tls.VersionTLS12,
			},
		},
		// RFC 8461 section 3.3: HTTPS redirects MUST NOT be followed. Returning
		// the last response surfaces any 3xx as a non-200 and fails the fetch,
		// which also defeats a redirect that would downgrade to http or change
		// host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mtasts: policy fetch returned HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxPolicyBody))
}

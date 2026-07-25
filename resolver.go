package mtasts

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
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
// (RFC 8461 §3.2 allows up to 31557600s / ~1 year).
const maxCacheTTL = maxMaxAge * time.Second

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

	mu       sync.Mutex
	cache    map[string]cacheEntry
	negCache map[string]negEntry
}

type cacheEntry struct {
	policy    *Policy
	id        string
	expiresAt time.Time
}

// negEntry records that discovery of policy id for a domain failed (fetch or
// parse) and must not be retried until expiresAt. The id scopes the suppression
// per RFC 8461 §3.3: a freshly published id is a new policy and is fetched
// immediately rather than served from a stale failure.
type negEntry struct {
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
//
// A fetch or parse failure for a discovered id is negative-cached for
// NegativeTTL (default 5 minutes). While that entry is live, a later Resolve
// that discovers the same id skips the HTTPS fetch and falls straight through to
// the cached-or-fail-open path, so a domain whose policy host is down or being
// blocked is not re-probed on every outbound message (RFC 8461 §3.3). The
// suppression is scoped to the id: a newly published id is fetched immediately.
func (r *Resolver) Resolve(ctx context.Context, domain string) (*Policy, error) {
	domain = normalizeHost(domain)
	if domain == "" {
		return nil, ErrNoPolicy
	}

	now := r.now()

	txts, err := r.lookupTXT(ctx, TXTName(domain))
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

	// Rate-limit re-probing of a policy host that recently failed for this same
	// id: serve any still-valid cached policy or fail open without a fresh fetch.
	if r.recentlyFailed(domain, id, now) {
		return r.cachedOrNoPolicy(domain, now)
	}

	body, err := r.fetchPolicy(ctx, PolicyURL(domain))
	if err != nil {
		r.storeFailure(domain, id, now)
		return r.cachedOrNoPolicy(domain, now)
	}
	policy, err := ParsePolicy(body)
	if err != nil {
		r.storeFailure(domain, id, now)
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

// recentlyFailed reports whether a fetch/parse for domain's current id failed
// within the negative-cache TTL. It is scoped to the id so that a rotated
// (newly published) id is never suppressed by the previous id's failure.
func (r *Resolver) recentlyFailed(domain, id string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, found := r.negCache[domain]
	return found && e.id == id && now.Before(e.expiresAt)
}

// storeFailure records that discovery of id for domain failed, suppressing
// re-fetch of the same id until now+negTTL.
func (r *Resolver) storeFailure(domain, id string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.negCache == nil {
		r.negCache = make(map[string]negEntry)
	}
	r.negCache[domain] = negEntry{id: id, expiresAt: now.Add(r.negTTL())}
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
	// ParsePolicy already bounds max_age to 1..maxMaxAge, but a directly
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
	r.cache[domain] = cacheEntry{policy: policy, id: id, expiresAt: now.Add(ttl)}
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

// parseTXTID extracts the policy id from the _mta-sts.<domain> TXT records.
// Exactly one record must be a syntactically valid MTA-STS TXT record per
// RFC 8461 §3.1; more than one valid record is ambiguous and anything else is
// treated as "no policy".
func parseTXTID(records []string) (string, bool) {
	found := 0
	id := ""
	for _, rec := range records {
		thisID, ok := parseSTSTextRecord(rec)
		if !ok {
			continue
		}
		found++
		id = thisID
	}
	if found != 1 {
		return "", false
	}
	return id, true
}

// parseSTSTextRecord validates a single TXT string against the RFC 8461 §3.1
// grammar and returns its policy id:
//
//	sts-text-record = sts-version 1*(field-delim sts-field) [field-delim]
//	sts-version     = "v=STSv1"
//	field-delim     = *WSP ";" *WSP
//	sts-field       = sts-id / sts-extension   ; sts-id required
//	sts-id          = "id=" 1*32(ALPHA / DIGIT)
//
// The record MUST lead with the exact "v=STSv1" token (no internal whitespace,
// which rules out "v = STSv1" and fields in the wrong order), MUST carry exactly
// one "id=" whose value is 1*32(ALPHA / DIGIT), and MUST NOT repeat the version
// field. Whitespace is permitted only around the ";" delimiters. Unrecognized
// extension fields are permitted and ignored. Any deviation yields ok=false so
// the caller treats the record as absent rather than discovering/caching a
// policy off a malformed or attacker-shaped record.
func parseSTSTextRecord(rec string) (id string, ok bool) {
	fields := strings.Split(strings.TrimSpace(rec), ";")
	// v=STSv1 MUST be the first field; the version token admits no internal
	// whitespace, so compare it exactly (the surrounding *WSP of the field-delim
	// is absorbed by the per-field TrimSpace below and around fields[0] here).
	if strings.TrimSpace(fields[0]) != "v="+Version {
		return "", false
	}
	sawID := false
	for _, f := range fields[1:] {
		f = strings.TrimSpace(f)
		switch {
		case f == "":
			// An empty trailing field ("v=STSv1; id=abc;") is a bare field-delim
			// with no content; tolerate it. A field-delim without an id, e.g.
			// "v=STSv1;", still fails below because sawID stays false.
			continue
		case strings.HasPrefix(f, "v="):
			// A repeated version field is malformed (RFC 8461 §3.1).
			return "", false
		case strings.HasPrefix(f, "id="):
			if sawID {
				return "", false // duplicate id field
			}
			v := strings.TrimPrefix(f, "id=")
			if !validSTSID(v) {
				return "", false
			}
			id, sawID = v, true
		default:
			// Unrecognized extension field (sts-extension): permitted, ignored.
		}
	}
	if !sawID {
		return "", false
	}
	return id, true
}

// validSTSID reports whether s satisfies the sts-id value grammar
// 1*32(ALPHA / DIGIT): between 1 and 32 characters, each an ASCII letter or
// digit.
func validSTSID(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
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
	// RFC 8461 section 3.2: the policy file is served as text/plain. Reject any
	// other media type so a misconfigured or hijacked host that answers the
	// policy URL with, e.g., an HTML error page or captive-portal body cannot
	// have that body handed to ParsePolicy (which is lenient about unknown
	// lines and could parse it into an unintended policy shape). The media type
	// is matched case-insensitively with its parameters ignored, so both
	// "text/plain" and "text/plain; charset=utf-8" are accepted; a missing or
	// unparseable Content-Type cannot be confirmed as text/plain and is likewise
	// rejected rather than trusted.
	mediaType, _, mtErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mtErr != nil || !strings.EqualFold(mediaType, "text/plain") {
		return nil, fmt.Errorf("mtasts: policy fetch returned Content-Type %q; require text/plain (RFC 8461 §3.2)", resp.Header.Get("Content-Type"))
	}
	// Read one byte past the cap so an oversize body can be detected and
	// REJECTED rather than silently truncated. Truncating at maxPolicyBody would
	// return a prefix of the real file with no error, letting the library parse
	// and enforce a policy the publisher never served (e.g. a trailing
	// "mode: none" dropped, leaving an "mode: enforce" prefix in force, or a
	// half-read mx: line minting an unintended pattern). RFC 8461 section 3.3
	// permits imposing a size limit; it does not sanction rewriting the policy
	// by truncation, so an oversize body is treated as no usable policy.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxPolicyBody {
		return nil, fmt.Errorf("mtasts: policy body exceeds %d bytes; refusing to parse a truncated policy (RFC 8461 §3.3)", maxPolicyBody)
	}
	return body, nil
}

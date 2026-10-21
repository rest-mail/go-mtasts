package mtasts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

// fetchCipherSuites are the TLS 1.2 suites a policy fetch offers: ECDHE key
// exchange with AES or ChaCha20, AEAD first. RFC 7525 section 4 rules out RC4
// and suites below 128 bits such as 3DES, and asks for forward secrecy, so
// static RSA key exchange is left out too. crypto/tls's defaults agree only
// while GODEBUG and the main module's go line leave them alone; naming the
// suites here keeps the fetch to them whatever program it is built into.
// TLS 1.3 suites are not configurable and all qualify.
var fetchCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
}

// maxCacheTTL caps how long a policy is cached regardless of its max_age
// (RFC 8461 §3.2 allows up to 31557600s / ~1 year).
const maxCacheTTL = maxMaxAge * time.Second

// refreshInterval is how long a cached policy is served before Resolve fetches
// it again even though its id is unchanged. RFC 8461 §3.3 says to refresh
// cached policies before they expire and suggests once per day; §10.2 explains
// why: an attacker who blocks the refresh must then do so for the policy's
// whole max_age, not just at the moment it runs out.
const refreshInterval = 24 * time.Hour

// errNoTXTRecord is passed to Resolver.RefreshFailed when the TXT lookup
// succeeds but finds no valid MTA-STS record.
var errNoTXTRecord = errors.New("mtasts: no valid _mta-sts TXT record")

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

	now := r.now()

	txts, err := r.lookupTXT(ctx, TXTName(domain))
	if err != nil {
		return r.cachedOrNoPolicy(domain, now, err)
	}
	id, ok := parseTXTID(txts)
	if !ok {
		return r.cachedOrNoPolicy(domain, now, errNoTXTRecord)
	}

	if p := r.cached(domain, id, now); p != nil {
		return p, nil
	}

	// Rate-limit re-probing of a policy host that recently failed for this same
	// id: serve any still-valid cached policy or fail open without a fresh fetch.
	if r.recentlyFailed(domain, id, now) {
		return r.cachedOrNoPolicy(domain, now, nil)
	}

	body, err := r.fetchPolicy(ctx, PolicyURL(domain))
	if err != nil {
		r.storeFailure(domain, id, now)
		return r.cachedOrNoPolicy(domain, now, err)
	}
	policy, err := ParsePolicy(body)
	if err != nil {
		r.storeFailure(domain, id, now)
		return r.cachedOrNoPolicy(domain, now, err)
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
// §3.3). failure is why discovery failed, or nil when no attempt was made (a
// negative-cached id); a cached policy served after a failure is reported to
// RefreshFailed unless its mode is "none".
func (r *Resolver) cachedOrNoPolicy(domain string, now time.Time, failure error) (*Policy, error) {
	r.mu.Lock()
	e, found := r.cache[domain]
	r.mu.Unlock()
	if !found || !now.Before(e.expiresAt) {
		return nil, ErrNoPolicy
	}
	if failure != nil && r.RefreshFailed != nil && e.policy.Mode != ModeNone {
		r.RefreshFailed(domain, e.policy, failure)
	}
	return e.policy, nil
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

// parseTXTID extracts the policy id from the _mta-sts.<domain> TXT records
// (RFC 8461 §3.1). Records that do not begin with "v=STSv1;" are discarded;
// exactly one must remain, and it must match the sts-text-record grammar.
// Otherwise the domain has no available policy.
func parseTXTID(records []string) (string, bool) {
	var sts []string
	for _, rec := range records {
		if rest, ok := strings.CutPrefix(rec, "v="+Version); ok && strings.HasPrefix(strings.TrimLeft(rest, " \t"), ";") {
			sts = append(sts, rec)
		}
	}
	if len(sts) != 1 {
		return "", false
	}
	return parseSTSTextRecord(sts[0])
}

// parseSTSTextRecord validates a single TXT string against the RFC 8461 §3.1
// grammar and returns its policy id:
//
//	sts-text-record = sts-version 1*(sts-field-delim sts-field) [sts-field-delim]
//	sts-version     = %s"v=STSv1"
//	sts-field-delim = *WSP ";" *WSP
//	sts-field       = sts-id / sts-extension   ; sts-id required
//	sts-id          = %s"id=" 1*32(ALPHA / DIGIT)
//	sts-extension   = sts-ext-name "=" sts-ext-value
//	sts-ext-name    = (ALPHA / DIGIT) *31(ALPHA / DIGIT / "_" / "-" / ".")
//	sts-ext-value   = 1*(%x21-3A / %x3C / %x3E-7E)
//
// The record must lead with the exact "v=STSv1" token, every field must match
// the grammar, and an "id=" field must be present. Whitespace is permitted only
// around the ";" delimiters. Unrecognized extension fields are ignored, and so
// is every repeat of a field after its first (RFC 8461 §3.2): a later "v=" or
// "id=" changes nothing. Any deviation yields ok=false so the caller treats the
// record as absent rather than discovering a policy off a malformed record.
func parseSTSTextRecord(rec string) (id string, ok bool) {
	s, found := strings.CutPrefix(rec, "v="+Version)
	if !found {
		return "", false
	}
	sawID := false
	for s != "" {
		s = strings.TrimLeft(s, " \t")
		if !strings.HasPrefix(s, ";") {
			return "", false
		}
		s = strings.TrimLeft(s[1:], " \t")
		if s == "" {
			break // the optional trailing delimiter
		}
		end := strings.IndexAny(s, " \t;")
		if end < 0 {
			end = len(s)
		}
		name, value, _ := strings.Cut(s[:end], "=")
		s = s[end:]
		if !validExtName(name) || !validExtValue(value) {
			return "", false
		}
		if name == "id" && !sawID {
			if !validSTSID(value) {
				return "", false
			}
			id, sawID = value, true
		}
	}
	return id, sawID
}

// validExtName reports whether s is an sts-ext-name: a letter or digit, then
// up to 31 letters, digits, "_", "-" or ".".
func validExtName(s string) bool {
	if s == "" || len(s) > 32 || !isAlnum(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !isAlnum(c) && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// validExtValue reports whether s is an sts-ext-value: one or more visible
// US-ASCII characters other than "=" and ";".
func validExtValue(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '=' || c == ';' {
			return false
		}
	}
	return true
}

// validSTSID reports whether s satisfies the sts-id value grammar
// 1*32(ALPHA / DIGIT): between 1 and 32 characters, each an ASCII letter or
// digit.
func validSTSID(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) {
			return false
		}
	}
	return true
}

// HTTPFetch fetches a policy file with a Fetcher that dials the network and
// trusts the system's root CAs; insecure is Fetcher.Insecure.
func HTTPFetch(ctx context.Context, url string, insecure bool) ([]byte, error) {
	f := Fetcher{Insecure: insecure}
	return f.Fetch(ctx, url)
}

// A Fetcher performs the HTTPS GET for a policy file. Per RFC 8461 section 3.3
// the policy MUST be fetched over HTTPS with a verified server certificate, and
// redirects MUST NOT be followed:
//
//   - The URL scheme is pinned to https. A non-https scheme is rejected so a
//     direct caller cannot fetch a policy over cleartext; only when Insecure is
//     explicitly set (a dev/test deployment) is a plaintext http URL permitted.
//   - The server certificate must be valid for the policy host
//     (mta-sts.<domain>) and chain to RootCAs, unless Insecure is set. TLS 1.2
//     is the minimum (RFC 8461 §7.2), and SNI names the policy host (§7.1).
//   - 3xx redirects are not followed, which also prevents a redirect from
//     downgrading the fetch to http or steering it to a different host — either
//     of which would defeat the policy origin.
//   - Nothing is cached or reused: every fetch opens a new connection and
//     closes it afterwards.
//
// A plaintext, invalid-certificate, or redirected fetch therefore fails rather
// than returning a policy. The zero value is ready to use.
type Fetcher struct {
	// DialContext opens the connection to the policy host. Nil means a
	// net.Dialer. Tests use it to serve a policy host from memory.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// RootCAs are the CAs a policy host's certificate must chain to. Nil means
	// the system's roots.
	RootCAs *x509.CertPool
	// Insecure skips certificate verification and permits a plaintext http URL.
	// It is for development deployments only and must not be set in production.
	Insecure bool
}

// Fetch fetches the policy file at url. It has the signature of a
// FetchPolicyFunc, so a Resolver can use it directly.
func (f *Fetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	switch req.URL.Scheme {
	case "https":
		// Verified HTTPS: the required transport for a policy fetch.
	case "http":
		if !f.Insecure {
			return nil, fmt.Errorf("mtasts: refusing to fetch policy over cleartext http (RFC 8461 requires https): %s", url)
		}
	default:
		return nil, fmt.Errorf("mtasts: unsupported policy URL scheme %q (RFC 8461 requires https)", req.URL.Scheme)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: f.DialContext,
			TLSClientConfig: &tls.Config{
				RootCAs:            f.RootCAs,
				InsecureSkipVerify: f.Insecure, //nolint:gosec // gated by caller; enforce path always passes false
				MinVersion:         tls.VersionTLS12,
				CipherSuites:       fetchCipherSuites,
			},
			// One connection per fetch, closed when it is done: a transport
			// made per call would otherwise keep its idle connection open.
			DisableKeepAlives: true,
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
	// is matched case-insensitively with its parameters ignored, as §3.2 says,
	// so "text/plain", "text/plain; charset=utf-8" and even a malformed
	// parameter are accepted; a missing or unparseable media type cannot be
	// confirmed as text/plain and is likewise rejected rather than trusted.
	mediaType, _, mtErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if (mtErr != nil && !errors.Is(mtErr, mime.ErrInvalidMediaParameter)) || !strings.EqualFold(mediaType, "text/plain") {
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

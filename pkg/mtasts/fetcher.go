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
	"time"
)

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

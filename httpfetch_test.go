package mtasts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHTTPFetchRejectsCleartext is the red-green guard for issue #10: a direct
// HTTPFetch call with an http:// URL must NOT perform a cleartext policy fetch.
// RFC 8461 section 3.3 requires the policy to be fetched over HTTPS. Before the
// fix this returned the body over plaintext.
func TestHTTPFetchRejectsCleartext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"))
	}))
	defer srv.Close()

	// Secure default (insecure=false) must refuse the http:// scheme rather
	// than fetch a policy over cleartext.
	if _, err := HTTPFetch(context.Background(), srv.URL, false); err == nil {
		t.Fatalf("HTTPFetch accepted cleartext http:// URL %q; want error", srv.URL)
	}

	// The explicit dev/test escape hatch (insecure=true) may still fetch over
	// http://.
	body, err := HTTPFetch(context.Background(), srv.URL, true)
	if err != nil {
		t.Fatalf("insecure HTTPFetch over http:// failed: %v", err)
	}
	if !strings.Contains(string(body), "STSv1") {
		t.Fatalf("insecure http:// fetch returned unexpected body: %q", body)
	}
}

// TestHTTPFetchVerifiesCertificate asserts HTTPFetch validates the server
// certificate on the secure path and only skips verification when the caller
// explicitly opts into insecure mode.
func TestHTTPFetchVerifiesCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"))
	}))
	defer srv.Close()

	// The untrusted (self-signed) cert must be rejected on the secure path.
	if _, err := HTTPFetch(context.Background(), srv.URL, false); err == nil {
		t.Fatalf("HTTPFetch accepted an untrusted TLS certificate; want a verification error")
	}

	// insecure=true skips verification (dev/test only).
	if _, err := HTTPFetch(context.Background(), srv.URL, true); err != nil {
		t.Fatalf("insecure HTTPFetch over self-signed TLS failed: %v", err)
	}
}

// TestHTTPFetchRejectsOversizedPolicy is the red-green guard for issue #9: a
// policy body larger than the read cap must be REJECTED, not silently truncated
// into a valid-looking policy. Here the publisher's real final directive
// (mode: none) sits past the 64 KB cap; truncation would drop it and leave the
// "mode: enforce" prefix in force — enforcing a policy the publisher never
// served. RFC 8461 section 3.3 permits imposing a size limit (rejecting an
// oversize body); nothing sanctions rewriting the policy by truncation. Before
// the fix HTTPFetch returned the truncated prefix with no error.
func TestHTTPFetchRejectsOversizedPolicy(t *testing.T) {
	prefix := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"
	padding := strings.Repeat("# pad\n", (maxPolicyBody/6)+1) // pushes total past the cap
	body := prefix + padding + "mode: none\n"
	if len(body) <= maxPolicyBody {
		t.Fatalf("test bug: body %d bytes is not larger than cap %d", len(body), maxPolicyBody)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	// insecure=true only to accept the plaintext test server; the size check is
	// independent of transport.
	got, err := HTTPFetch(context.Background(), srv.URL, true)
	if err == nil {
		t.Fatalf("HTTPFetch accepted a %d-byte policy (cap %d) and returned %d bytes; "+
			"want an error rather than a silently truncated policy", len(body), maxPolicyBody, len(got))
	}
}

// TestHTTPFetchAcceptsMaxSizedPolicy guards against over-tightening: a body
// exactly at the cap must still be accepted intact. The reject must fire only
// when the body exceeds maxPolicyBody, not when it equals it.
func TestHTTPFetchAcceptsMaxSizedPolicy(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"
	body += strings.Repeat("#", maxPolicyBody-len(body)) // pad to exactly the cap
	if len(body) != maxPolicyBody {
		t.Fatalf("test bug: body %d bytes, want exactly %d", len(body), maxPolicyBody)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := HTTPFetch(context.Background(), srv.URL, true)
	if err != nil {
		t.Fatalf("HTTPFetch rejected a cap-sized (%d-byte) policy: %v", maxPolicyBody, err)
	}
	if len(got) != maxPolicyBody {
		t.Fatalf("HTTPFetch returned %d bytes for a cap-sized policy; want %d", len(got), maxPolicyBody)
	}
}

// TestHTTPFetchDoesNotFollowRedirect asserts RFC 8461 section 3.3: a 3xx
// redirect (here a downgrade to http://) is not followed and fails the fetch
// instead of yielding a policy from the redirect target.
func TestHTTPFetchDoesNotFollowRedirect(t *testing.T) {
	// Cleartext target the redirect tries to steer the fetch to.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("version: STSv1\nmode: enforce\nmx: evil.example.com\nmax_age: 86400\n"))
	}))
	defer target.Close()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer srv.Close()

	// insecure=true so the self-signed cert is accepted; the downgrade redirect
	// must still not be followed.
	if _, err := HTTPFetch(context.Background(), srv.URL, true); err == nil {
		t.Fatalf("HTTPFetch followed a downgrade redirect; want error")
	}
}

// TestHTTPFetchRejectsNonTextPlain is the red-green guard for issue #12: a
// policy response served with a non-text/plain media type (here text/html, as a
// captive portal or HTTP error page would use) MUST be rejected even when the
// body itself would parse as a valid policy. RFC 8461 §3.2 serves the policy as
// text/plain; accepting any media type lets a misconfigured or hijacked host
// have an HTML (or other) body handed to ParsePolicy. Before the fix HTTPFetch
// ignored Content-Type entirely and returned the body.
func TestHTTPFetchRejectsNonTextPlain(t *testing.T) {
	validBody := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"
	// Media types that MUST be rejected. The empty case covers a response with
	// no Content-Type at all: the media type cannot be confirmed as text/plain,
	// so it is treated as a mismatch rather than trusted.
	for _, ct := range []string{
		"text/html",
		"text/html; charset=utf-8",
		"application/json",
		"application/octet-stream",
		"multipart/form-data; boundary=x",
		"", // no Content-Type header
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Setting the header (even to "") suppresses Go's content sniffing so
			// the test controls the media type exactly.
			w.Header()["Content-Type"] = []string{ct}
			_, _ = w.Write([]byte(validBody))
		}))
		got, err := HTTPFetch(context.Background(), srv.URL, true)
		srv.Close()
		if err == nil {
			t.Fatalf("HTTPFetch accepted a policy served as Content-Type %q and returned %d bytes; "+
				"want a media-type rejection", ct, len(got))
		}
	}
}

// TestHTTPFetchAcceptsTextPlain guards against over-tightening the issue #12
// fix: a policy served as text/plain must still be accepted regardless of an
// added charset parameter, header case, or surrounding whitespace. The media
// type match is case-insensitive and ignores parameters (RFC 8461 §3.2).
func TestHTTPFetchAcceptsTextPlain(t *testing.T) {
	validBody := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"
	for _, ct := range []string{
		"text/plain",
		"text/plain; charset=utf-8",
		"text/plain;charset=utf-8",
		"Text/Plain; charset=UTF-8",
		"TEXT/PLAIN",
		"  text/plain  ",
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", ct)
			_, _ = w.Write([]byte(validBody))
		}))
		got, err := HTTPFetch(context.Background(), srv.URL, true)
		srv.Close()
		if err != nil {
			t.Fatalf("HTTPFetch rejected a text/plain policy (Content-Type %q): %v", ct, err)
		}
		if !strings.Contains(string(got), "STSv1") {
			t.Fatalf("HTTPFetch(Content-Type %q) returned unexpected body: %q", ct, got)
		}
	}
}

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

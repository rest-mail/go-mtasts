package mtasts

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPolicyBody = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"

// testCA is a certificate authority made for one test, so a policy host can be
// served from memory with a certificate the Fetcher is told to trust.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-mtasts test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// leaf issues a server certificate. tweak may change the template, to drop the
// SANs or move the validity window, before it is signed.
func (ca *testCA) leaf(t *testing.T, dnsNames []string, tweak func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "policy host"},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if tweak != nil {
		tweak(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// policyHost serves handler over TLS with cert and returns a Fetcher whose
// every connection reaches it, whatever host the URL names, and which trusts
// ca. cfg, if not nil, adjusts the server's TLS configuration.
func policyHost(t *testing.T, ca *testCA, cert tls.Certificate, handler http.Handler, cfg func(*tls.Config)) (*Fetcher, *httptest.Server) {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	if cfg != nil {
		cfg(srv.TLS)
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	f := &Fetcher{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		RootCAs: ca.pool,
	}
	return f, srv
}

func servePolicy(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	})
}

// TestTXTNameAndPolicyURL checks the two names discovery derives from a Policy
// Domain: the TXT record name and the policy URL.
//
// checklist: MTASTS-TXT-01 MTASTS-POL-01
func TestTXTNameAndPolicyURL(t *testing.T) {
	if got, want := TXTName("Example.COM."), "_mta-sts.example.com"; got != want {
		t.Errorf("TXTName = %q, want %q", got, want)
	}
	if got, want := PolicyURL("Example.COM."), "https://mta-sts.example.com/.well-known/mta-sts.txt"; got != want {
		t.Errorf("PolicyURL = %q, want %q", got, want)
	}
}

// TestFetcherSendsGET checks the request a policy fetch makes: a GET for the
// well-known path on the policy host.
//
// checklist: MTASTS-POL-01
func TestFetcherSendsGET(t *testing.T) {
	ca := newTestCA(t)
	var method, host, path string
	f, _ := policyHost(t, ca, ca.leaf(t, []string{"mta-sts.example.com"}, nil), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, host, path = r.Method, r.Host, r.URL.Path
		servePolicy(testPolicyBody).ServeHTTP(w, r)
	}), nil)
	body, err := f.Fetch(context.Background(), PolicyURL("example.com"))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(body) != testPolicyBody {
		t.Errorf("body = %q, want %q", body, testPolicyBody)
	}
	if method != http.MethodGet || host != "mta-sts.example.com" || path != "/.well-known/mta-sts.txt" {
		t.Errorf("request = %s %s%s, want GET mta-sts.example.com/.well-known/mta-sts.txt", method, host, path)
	}
}

// TestFetcherSendsSNI checks that the TLS handshake names the policy host.
//
// checklist: MTASTS-FETCH-14
func TestFetcherSendsSNI(t *testing.T) {
	ca := newTestCA(t)
	var mu sync.Mutex
	var sni string
	f, _ := policyHost(t, ca, ca.leaf(t, []string{"mta-sts.example.com"}, nil), servePolicy(testPolicyBody), func(c *tls.Config) {
		c.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			sni = hello.ServerName
			mu.Unlock()
			return nil, nil
		}
	})
	if _, err := f.Fetch(context.Background(), PolicyURL("example.com")); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if sni != "mta-sts.example.com" {
		t.Errorf("SNI = %q, want mta-sts.example.com", sni)
	}
}

// TestFetcherVerifiesCertificate checks that the policy host's certificate
// must name the host, chain to a trusted root and be within its validity.
//
// checklist: MTASTS-FETCH-02
func TestFetcherVerifiesCertificate(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	host := []string{"mta-sts.example.com"}
	cases := []struct {
		name string
		cert tls.Certificate
		ok   bool
	}{
		{"valid", ca.leaf(t, host, nil), true},
		{"wrong name", ca.leaf(t, []string{"mta-sts.example.org"}, nil), false},
		{"untrusted issuer", other.leaf(t, host, nil), false},
		{"expired", ca.leaf(t, host, func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-2 * time.Hour)
			c.NotAfter = time.Now().Add(-time.Hour)
		}), false},
		{"not yet valid", ca.leaf(t, host, func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(time.Hour)
			c.NotAfter = time.Now().Add(2 * time.Hour)
		}), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, _ := policyHost(t, ca, c.cert, servePolicy(testPolicyBody), nil)
			_, err := f.Fetch(context.Background(), PolicyURL("example.com"))
			if (err == nil) != c.ok {
				t.Fatalf("Fetch error = %v, want ok=%v", err, c.ok)
			}
		})
	}
}

// TestFetcherMatchesOnlyDNSIDs checks that the policy host is matched against
// the certificate's DNS-IDs alone, with a wildcard only as a whole left-most
// label.
//
// checklist: MTASTS-FETCH-03
func TestFetcherMatchesOnlyDNSIDs(t *testing.T) {
	ca := newTestCA(t)
	cases := []struct {
		name string
		cert tls.Certificate
		ok   bool
	}{
		{"subject CN only", ca.leaf(t, nil, func(c *x509.Certificate) { c.Subject.CommonName = "mta-sts.example.com" }), false},
		{"left-most wildcard", ca.leaf(t, []string{"*.example.com"}, nil), true},
		{"partial-label wildcard", ca.leaf(t, []string{"mta-*.example.com"}, nil), false},
		{"wildcard one level too deep", ca.leaf(t, []string{"*.mta-sts.example.com"}, nil), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, _ := policyHost(t, ca, c.cert, servePolicy(testPolicyBody), nil)
			_, err := f.Fetch(context.Background(), PolicyURL("example.com"))
			if (err == nil) != c.ok {
				t.Fatalf("Fetch error = %v, want ok=%v", err, c.ok)
			}
		})
	}
}

// TestFetcherRequiresStatus200 checks that only a 200 response is a policy.
//
// checklist: MTASTS-FETCH-05
func TestFetcherRequiresStatus200(t *testing.T) {
	ca := newTestCA(t)
	for _, status := range []int{http.StatusCreated, http.StatusNoContent, http.StatusNotModified, http.StatusNotFound, http.StatusInternalServerError} {
		f, _ := policyHost(t, ca, ca.leaf(t, []string{"mta-sts.example.com"}, nil), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(testPolicyBody))
		}), nil)
		if body, err := f.Fetch(context.Background(), PolicyURL("example.com")); err == nil {
			t.Errorf("status %d: Fetch returned %q, want an error", status, body)
		}
	}
}

// TestFetcherDoesNotCache checks that every fetch goes to the policy host on a
// connection of its own, whatever caching headers the host sends.
//
// checklist: MTASTS-FETCH-07
func TestFetcherDoesNotCache(t *testing.T) {
	ca := newTestCA(t)
	var mu sync.Mutex
	requests, conns := 0, 0
	f, _ := policyHost(t, ca, ca.leaf(t, []string{"mta-sts.example.com"}, nil), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requests++
		n := requests
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(strings.Replace(testPolicyBody, "86400", strings.Repeat("1", n), 1)))
	}), nil)
	// Count connections where the Fetcher dials them: the server is already
	// running, so setting its ConnState now would race with its goroutines.
	dial := f.DialContext
	f.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		conns++
		mu.Unlock()
		return dial(ctx, network, addr)
	}
	first, err := f.Fetch(context.Background(), PolicyURL("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.Fetch(context.Background(), PolicyURL("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) == string(second) {
		t.Error("second fetch returned the first body: it was served from a cache")
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 2 || conns != 2 {
		t.Errorf("requests = %d, connections = %d; want 2 and 2", requests, conns)
	}
}

// TestFetcherRequiresTLS12 checks that the fetch refuses a policy host that
// offers nothing newer than TLS 1.1.
//
// checklist: MTASTS-FETCH-15
func TestFetcherRequiresTLS12(t *testing.T) {
	ca := newTestCA(t)
	f, _ := policyHost(t, ca, ca.leaf(t, []string{"mta-sts.example.com"}, nil), servePolicy(testPolicyBody), func(c *tls.Config) {
		c.MinVersion = tls.VersionTLS10
		c.MaxVersion = tls.VersionTLS11
	})
	if _, err := f.Fetch(context.Background(), PolicyURL("example.com")); err == nil {
		t.Fatal("Fetch over TLS 1.1 succeeded, want an error")
	}
}

// TestFetcherHonoursContext checks that a fetch stops when its context ends,
// so a caller can bound how long a slow policy host holds up delivery.
//
// checklist: MTASTS-FETCH-09
func TestFetcherHonoursContext(t *testing.T) {
	ca := newTestCA(t)
	release := make(chan struct{})
	f, _ := policyHost(t, ca, ca.leaf(t, []string{"mta-sts.example.com"}, nil), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}), nil)
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := f.Fetch(ctx, PolicyURL("example.com")); err == nil {
		t.Fatal("Fetch from a host that never answers succeeded")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Fetch took %v after its context ended", d)
	}
}

// TestFetcherRejectsOtherSchemes checks that a URL that is neither https nor,
// when Insecure is set, http is refused before any connection is made.
//
// checklist: MTASTS-FETCH-01
func TestFetcherRejectsOtherSchemes(t *testing.T) {
	dialed := false
	f := &Fetcher{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, net.ErrClosed
		},
		Insecure: true,
	}
	for _, url := range []string{"ftp://mta-sts.example.com/.well-known/mta-sts.txt", "file:///etc/passwd", "gopher://mta-sts.example.com/"} {
		if _, err := f.Fetch(context.Background(), url); err == nil {
			t.Errorf("Fetch(%q) succeeded, want an error", url)
		}
	}
	if _, err := f.Fetch(context.Background(), "://bad"); err == nil {
		t.Error("Fetch of an unparseable URL succeeded")
	}
	if dialed {
		t.Error("Fetch dialled for a URL it should have refused")
	}
}

// TestFetcherBodyReadError checks that a policy body cut short by the host
// closing the connection is an error, not the partial policy.
//
// checklist: MTASTS-FETCH-09
func TestFetcherBodyReadError(t *testing.T) {
	ca := newTestCA(t)
	f, _ := policyHost(t, ca, ca.leaf(t, []string{"mta-sts.example.com"}, nil), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1000\r\n\r\nversion: STSv1\n")
		_ = buf.Flush()
		_ = conn.Close()
	}), nil)
	if body, err := f.Fetch(context.Background(), PolicyURL("example.com")); err == nil {
		t.Fatalf("Fetch returned %q from a truncated body, want an error", body)
	}
}

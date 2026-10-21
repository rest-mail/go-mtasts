package mtasts

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// rsaLeaf issues an RSA server certificate, which a static RSA key exchange
// needs; ca.leaf issues ECDSA ones.
func (ca *testCA) rsaLeaf(t *testing.T, dnsNames []string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "policy host"},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestFetcherFollowsRFC7525 checks the TLS 1.2 cipher suites a policy fetch
// will agree to against RFC 7525 section 4: never RC4 (4.1), never a suite
// below 128 bits such as 3DES (4.1), and only forward-secret key exchange
// (4.2, 6.3), while the recommended ECDHE AEAD suites work. GODEBUG turns the
// static RSA and 3DES suites back on in crypto/tls's defaults, as a program
// whose go.mod names an older Go gets them, so the fetch must hold to this
// itself rather than lean on the defaults.
//
// checklist: MTASTS-FETCH-16
func TestFetcherFollowsRFC7525(t *testing.T) {
	t.Setenv("GODEBUG", "tlsrsakex=1,tls3des=1")
	ca := newTestCA(t)
	cert := ca.rsaLeaf(t, []string{"mta-sts.example.com"})
	for _, tc := range []struct {
		name   string
		suites []uint16
		ok     bool
	}{
		{"RC4", []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA}, false},
		{"3DES", []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}, false},
		{"static RSA key exchange", []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_CBC_SHA}, false},
		{"ECDHE AES-128-GCM", []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, true},
		{"ECDHE AES-256-GCM", []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}, true},
		{"ECDHE ChaCha20-Poly1305", []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}, true},
		{"ECDHE AES-CBC", []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := policyHost(t, ca, cert, servePolicy(testPolicyBody), func(c *tls.Config) {
				c.MaxVersion = tls.VersionTLS12
				c.CipherSuites = tc.suites
			})
			body, err := f.Fetch(context.Background(), PolicyURL("example.com"))
			switch {
			case tc.ok && err != nil:
				t.Fatalf("Fetch: %v", err)
			case tc.ok && string(body) != testPolicyBody:
				t.Fatalf("Fetch returned %q", body)
			case !tc.ok && err == nil:
				t.Fatal("Fetch succeeded, want the handshake refused")
			}
		})
	}
}

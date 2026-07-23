package mtasts

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"
)

func TestParsePolicy(t *testing.T) {
	t.Run("valid enforce", func(t *testing.T) {
		body := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n"
		p, err := ParsePolicy([]byte(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Version != "STSv1" || p.Mode != ModeEnforce || p.MaxAge != 604800 {
			t.Fatalf("bad fields: %+v", p)
		}
		if !reflect.DeepEqual(p.MX, []string{"mail.example.com", "*.example.net"}) {
			t.Fatalf("bad mx: %v", p.MX)
		}
	})

	t.Run("CRLF and spacing tolerated", func(t *testing.T) {
		body := "version:STSv1\r\nmode:  testing \r\nmx:   mx1.example.com  \r\nmax_age: 86400\r\n"
		p, err := ParsePolicy([]byte(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Mode != ModeTesting || len(p.MX) != 1 || p.MX[0] != "mx1.example.com" {
			t.Fatalf("bad parse: %+v", p)
		}
	})

	t.Run("mode none needs no mx", func(t *testing.T) {
		if _, err := ParsePolicy([]byte("version: STSv1\nmode: none\nmax_age: 12345\n")); err != nil {
			t.Fatalf("mode none should parse: %v", err)
		}
	})

	invalid := map[string]string{
		"wrong version":       "version: STSv2\nmode: enforce\nmx: a.example.com\nmax_age: 100\n",
		"missing version":     "mode: enforce\nmx: a.example.com\nmax_age: 100\n",
		"bad mode":            "version: STSv1\nmode: strict\nmx: a.example.com\nmax_age: 100\n",
		"missing max_age":     "version: STSv1\nmode: enforce\nmx: a.example.com\n",
		"zero max_age":        "version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 0\n",
		"non-numeric max_age": "version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 100days\n",
		"enforce without mx":  "version: STSv1\nmode: enforce\nmax_age: 100\n",
	}
	for name, body := range invalid {
		t.Run("invalid/"+name, func(t *testing.T) {
			if p, err := ParsePolicy([]byte(body)); err == nil {
				t.Fatalf("expected error, got policy %+v", p)
			}
		})
	}
}

func TestMatchesMX(t *testing.T) {
	p := &Policy{MX: []string{"mail.example.com", "*.mx.example.org"}}
	cases := []struct {
		host string
		want bool
	}{
		{"mail.example.com", true},       // exact
		{"MAIL.EXAMPLE.COM", true},       // case-insensitive
		{"mail.example.com.", true},      // trailing dot
		{"a.mx.example.org", true},       // wildcard, one label
		{"b.mx.example.org", true},       // wildcard, one label
		{"mx.example.org", false},        // wildcard must not match bare base
		{"a.b.mx.example.org", false},    // wildcard matches exactly one label
		{"mail.example.org", false},      // different domain
		{"evil-mail.example.com", false}, // not a subdomain relationship
		{"", false},                      // empty
	}
	for _, c := range cases {
		if got := p.MatchesMX(c.host); got != c.want {
			t.Errorf("MatchesMX(%q) = %v, want %v", c.host, got, c.want)
		}
	}
	if (&Policy{}).MatchesMX("anything") {
		t.Error("empty policy should match nothing")
	}
	var nilPolicy *Policy
	if nilPolicy.MatchesMX("x") {
		t.Error("nil policy should match nothing")
	}
}

func TestMatchesCert(t *testing.T) {
	policy := &Policy{MX: []string{"mail.example.com", "*.mx.example.org"}}

	cases := []struct {
		name string
		cert *x509.Certificate
		want bool
	}{
		{"exact SAN", &x509.Certificate{DNSNames: []string{"mail.example.com"}}, true},
		{"concrete SAN under policy wildcard", &x509.Certificate{DNSNames: []string{"a.mx.example.org"}}, true},
		{"wildcard cert SAN covers concrete policy host", &x509.Certificate{DNSNames: []string{"*.example.com"}}, true},
		{"CN fallback", &x509.Certificate{Subject: pkix.Name{CommonName: "mail.example.com"}}, true},
		{"no matching SAN", &x509.Certificate{DNSNames: []string{"mail.other.com"}}, false},
		{"nil cert", nil, false},
	}
	for _, c := range cases {
		if got := policy.MatchesCert(c.cert); got != c.want {
			t.Errorf("%s: MatchesCert = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCertNameWildcardCoversConcretePolicy(t *testing.T) {
	// A cert presenting a wildcard SAN "*.mx.example.org" should satisfy a
	// policy that names a concrete host under that wildcard.
	policy := &Policy{MX: []string{"a.mx.example.org"}}
	cert := &x509.Certificate{DNSNames: []string{"*.mx.example.org"}}
	if !policy.MatchesCert(cert) {
		t.Error("wildcard cert SAN should cover concrete policy host")
	}
}

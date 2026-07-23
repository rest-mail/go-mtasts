// Package mtasts implements MTA-STS (RFC 8461) policy discovery, caching, and
// enforcement for outbound SMTP delivery.
//
// A sending MTA discovers a recipient domain's policy by first reading the
// _mta-sts.<domain> TXT record (which carries a policy id) and then fetching
// the policy file from https://mta-sts.<domain>/.well-known/mta-sts.txt. When
// the policy mode is "enforce" the sender MUST negotiate STARTTLS to an MX host
// that is (a) named by the policy and (b) presents a certificate that is valid
// for that MX host; otherwise delivery must be refused rather than sent in the
// clear.
package mtasts

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// Policy modes (RFC 8461 section 5).
const (
	ModeEnforce = "enforce"
	ModeTesting = "testing"
	ModeNone    = "none"
)

// Version is the only MTA-STS policy version defined by RFC 8461.
const Version = "STSv1"

// Policy is a parsed MTA-STS policy file.
type Policy struct {
	Version string   // always "STSv1"
	Mode    string   // "enforce", "testing", or "none"
	MX      []string // MX host patterns; may use a single leading-label wildcard, e.g. "*.example.com"
	MaxAge  int      // policy lifetime in seconds
}

// ParsePolicy parses the body of an MTA-STS policy file (RFC 8461 section 3.2).
//
// It is deliberately lenient about unknown keys (per the spec) but strict about
// the fields required to make an enforcement decision: version must be STSv1,
// mode must be one of the defined values, max_age must be a positive integer,
// and at least one mx pattern must be present unless the mode is "none".
func ParsePolicy(body []byte) (*Policy, error) {
	p := &Policy{}
	sawMaxAge := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "version":
			p.Version = value
		case "mode":
			p.Mode = value
		case "mx":
			if value != "" {
				p.MX = append(p.MX, value)
			}
		case "max_age":
			n, err := parseUint(value)
			if err != nil {
				return nil, fmt.Errorf("mtasts: invalid max_age %q: %w", value, err)
			}
			p.MaxAge = n
			sawMaxAge = true
		}
	}

	if p.Version != Version {
		return nil, fmt.Errorf("mtasts: unsupported version %q", p.Version)
	}
	switch p.Mode {
	case ModeEnforce, ModeTesting, ModeNone:
	default:
		return nil, fmt.Errorf("mtasts: invalid mode %q", p.Mode)
	}
	if !sawMaxAge || p.MaxAge <= 0 {
		return nil, fmt.Errorf("mtasts: missing or non-positive max_age")
	}
	if p.Mode != ModeNone && len(p.MX) == 0 {
		return nil, fmt.Errorf("mtasts: mode %q requires at least one mx", p.Mode)
	}
	return p, nil
}

// parseUint parses a non-negative base-10 integer, rejecting anything with
// stray characters (fmt.Sscanf would silently accept "123abc").
func parseUint(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("non-digit %q", r)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

// MatchesMX reports whether a concrete MX hostname is named by the policy.
//
// Patterns are matched per RFC 8461 section 4.1 / RFC 6125: an exact
// (case-insensitive) match, or a single leading wildcard label ("*.example.com")
// that matches exactly one DNS label ("mail.example.com" but not "example.com"
// nor "a.b.example.com").
func (p *Policy) MatchesMX(host string) bool {
	if p == nil {
		return false
	}
	host = normalizeHost(host)
	for _, pattern := range p.MX {
		if hostMatchesPattern(host, normalizeHost(pattern)) {
			return true
		}
	}
	return false
}

// MatchesCert reports whether any identity presented by cert is named by the
// policy. It handles wildcards on either side: a policy wildcard covering a
// concrete cert name, or a wildcard cert name covering a concrete policy entry.
//
// Note: this is decision logic exercised by tests. The production send path
// enforces certificate validity by requiring the STARTTLS handshake to verify
// the certificate against the MX hostname (which MatchesMX has already confirmed
// is named by the policy); net/smtp does not expose the negotiated
// tls.ConnectionState, so MatchesCert is not called against the live socket.
func (p *Policy) MatchesCert(cert *x509.Certificate) bool {
	if p == nil || cert == nil {
		return false
	}
	names := cert.DNSNames
	if len(names) == 0 && cert.Subject.CommonName != "" {
		names = []string{cert.Subject.CommonName}
	}
	for _, name := range names {
		name = normalizeHost(name)
		for _, pattern := range p.MX {
			if certNameMatchesPattern(name, normalizeHost(pattern)) {
				return true
			}
		}
	}
	return false
}

// normalizeHost lower-cases a hostname and strips a trailing root dot.
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// hostMatchesPattern matches a concrete host against a policy pattern that may
// carry a single leading wildcard label.
func hostMatchesPattern(host, pattern string) bool {
	if host == "" || pattern == "" {
		return false
	}
	if host == pattern {
		return true
	}
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		// "*.example.com" matches "mail.example.com": host must end in
		// ".example.com" and contribute exactly one extra label.
		return strings.HasSuffix(host, "."+suffix) &&
			strings.Count(host, ".") == strings.Count(suffix, ".")+1
	}
	return false
}

// certNameMatchesPattern matches a certificate identity (which may itself be a
// wildcard) against a policy pattern (which may also be a wildcard).
func certNameMatchesPattern(certName, pattern string) bool {
	if certName == pattern {
		return true
	}
	// Concrete cert name covered by a wildcard policy pattern.
	if strings.HasPrefix(pattern, "*.") && !strings.HasPrefix(certName, "*.") {
		return hostMatchesPattern(certName, pattern)
	}
	// Wildcard cert name covering a concrete policy pattern.
	if strings.HasPrefix(certName, "*.") && !strings.HasPrefix(pattern, "*.") {
		return hostMatchesPattern(pattern, certName)
	}
	return false
}

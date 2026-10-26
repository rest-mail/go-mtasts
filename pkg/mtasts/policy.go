package mtasts

import (
	"crypto/x509"

	"github.com/rest-mail/go-mtasts/pkg/mtasts/internal/domainname"
	"github.com/rest-mail/go-mtasts/pkg/mtasts/internal/policygrammar"
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
// It is deliberately lenient about layout and unknown keys (per the spec) but
// strict about the fields required to make an enforcement decision: version
// must be STSv1, mode must be one of the defined values, max_age must be 1 to
// 10 digits in the range 0..31557600, every mx must be a DNS name in A-label
// form, optionally behind a "*." wildcard (RFC 8461 §3.2), and at least one mx
// pattern must be present unless the mode is "none".
func ParsePolicy(body []byte) (*Policy, error) {
	p, err := policygrammar.Parse(body)
	return (*Policy)(p), err
}

// MatchesMX reports whether a concrete MX hostname is named by the policy.
//
// Patterns are matched per RFC 8461 section 4.1 / RFC 6125: an exact
// (case-insensitive) match, or a single leading wildcard label ("*.example.com")
// that matches exactly one DNS label ("mail.example.com" but not "example.com"
// nor "a.b.example.com"). A host that is not itself a DNS name, such as
// "*.example.com", matches nothing, and neither does a pattern ParsePolicy
// would refuse, such as a bare "*", in a Policy built by hand.
func (p *Policy) MatchesMX(host string) bool {
	if p == nil {
		return false
	}
	return domainname.MatchesMX(p.MX, host)
}

// MatchesCert reports whether any DNS-ID presented by cert is named by the
// policy. It handles wildcards on either side: a policy wildcard covering a
// concrete cert name, or a wildcard cert name covering a concrete policy entry.
// Only the subject alternative names count: RFC 8461 §4.2 requires a SAN
// DNS-ID, so a certificate naming its host only in the subject common name
// matches nothing.
//
// MatchesCert compares names only; it does not itself verify that the
// certificate chains to a trusted root. A typical send path lets the STARTTLS
// handshake verify the presented certificate against the MX hostname (which
// MatchesMX has already confirmed the policy names), so this method is most
// useful for offline policy analysis and tests rather than gating a live
// socket.
func (p *Policy) MatchesCert(cert *x509.Certificate) bool {
	if p == nil || cert == nil {
		return false
	}
	for _, name := range cert.DNSNames {
		name = domainname.NormalizeHost(name)
		for _, pattern := range p.MX {
			if domainname.CertNameMatchesPattern(name, domainname.NormalizeHost(pattern)) {
				return true
			}
		}
	}
	return false
}

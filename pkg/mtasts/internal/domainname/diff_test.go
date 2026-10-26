package domainname

import (
	"strings"
	"testing"

	foxmtasts "github.com/foxcpp/go-mtasts"
)

// diffMX are pattern and host pairs on which this library and
// github.com/foxcpp/go-mtasts (MIT) must agree.
var diffMX = [][2]string{
	{"mail.example.com", "mail.example.com"},
	{"mail.example.com", "MAIL.EXAMPLE.COM."},
	{"mail.example.com.", "mail.example.com"},
	{"mail.example.com", "mail.example.org"},
	{"mail.example.com", "a.mail.example.com"},
	{"*.example.com", "mail.example.com"},
	{"*.example.com", "MX1.Example.Com."},
	{"*.example.com", "example.com"},
	{"*.example.com", "a.b.example.com"},
	{"*.example.com", "mail.example.org"},
	{"*.example.com.", "mail.example.com"},
	{"*.mx.example.com", "a.mx.example.com"},
	{"*.mx.example.com", "mx.example.com"},
	{"localhost", "localhost"},
	{"xn--bcher-kva.example", "xn--bcher-kva.example"},
	{"*.xn--bcher-kva.example", "MX.xn--bcher-kva.example"},
}

// diffComparable reports whether a pattern and host are ones the two
// libraries are meant to agree on. They disagree on purpose elsewhere:
//
//   - go-mtasts accepts U-labels and converts them; RFC 8461 §3.2 wants
//     A-labels in a policy, and DNS gives MX hosts as A-labels, so this library
//     refuses U-labels.
//   - go-mtasts lets "*.example.com" match ".example.com", an empty left-most
//     label; RFC 8461 §4.1 says the wildcard matches one whole label.
//   - go-mtasts takes a pattern or host that is not a DNS name (a bare "*",
//     "a..b", "a_b", "mail " with a space) as it is; this library matches
//     nothing to it.
//   - go-mtasts skips an "xn--" label that is not valid punycode, or that is
//     written "XN--"; this library compares it as the letters it is,
//     ignoring case.
func diffComparable(pattern, host string) bool {
	return ValidMXPattern(pattern) && ValidDomain(host) &&
		!strings.Contains(strings.ToLower(pattern+host), "xn--") || isDiffVector(pattern, host)
}

func isDiffVector(pattern, host string) bool {
	for _, v := range diffMX {
		if v[0] == pattern && v[1] == host {
			return true
		}
	}
	return false
}

// TestDiffMatchesMX compares MX matching with go-mtasts on the vectors above.
//
// checklist: MTASTS-MX-02 MTASTS-MX-03
func TestDiffMatchesMX(t *testing.T) {
	for _, v := range diffMX {
		ours := MatchesMX([]string{v[0]}, v[1])
		theirs := foxmtasts.Policy{MX: []string{v[0]}}.Match(v[1])
		if ours != theirs {
			t.Errorf("pattern %q, host %q: MatchesMX = %v, go-mtasts = %v", v[0], v[1], ours, theirs)
		}
	}
	// The disagreements diffComparable lists, each checked so the list stays
	// true.
	for _, v := range [][2]string{
		{"*.example.com", ".example.com"},
		{"a..b", "a..b"},
		{"mail.bücher.example", "mail.bücher.example"},
	} {
		ours := MatchesMX([]string{v[0]}, v[1])
		theirs := foxmtasts.Policy{MX: []string{v[0]}}.Match(v[1])
		if ours || !theirs || diffComparable(v[0], v[1]) {
			t.Errorf("pattern %q, host %q: MatchesMX = %v, go-mtasts = %v; want a listed disagreement", v[0], v[1], ours, theirs)
		}
	}
}

package domainname

import "strings"

// MatchesMX reports whether host is named by one of the policy patterns.
func MatchesMX(patterns []string, host string) bool {
	if !ValidDomain(host) {
		return false
	}
	host = NormalizeHost(host)
	for _, pattern := range patterns {
		if ValidMXPattern(pattern) && hostMatchesPattern(host, NormalizeHost(pattern)) {
			return true
		}
	}
	return false
}

// NormalizeHost lower-cases a hostname and strips a trailing root dot.
func NormalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// hostMatchesPattern matches a concrete host against a policy pattern that may
// carry a single leading wildcard label.
//
// Matching is per label, not per dot: host and pattern must have the same
// number of labels. A leading "*" label matches any single non-empty label
// ("*.example.com" matches "mail.example.com" but neither the bare
// "example.com" — no leading label — nor "a.b.example.com" — two labels — nor
// ".example.com" — an empty leading label). Every remaining label must match
// exactly. Callers pass already-normalized (lower-cased, root-dot-trimmed)
// names, so the label comparison is effectively case-insensitive.
func hostMatchesPattern(host, pattern string) bool {
	if host == "" || pattern == "" {
		return false
	}
	hostLabels := strings.Split(host, ".")
	patLabels := strings.Split(pattern, ".")
	if len(hostLabels) != len(patLabels) {
		return false
	}
	for i, pl := range patLabels {
		hl := hostLabels[i]
		if i == 0 && pl == "*" {
			// A wildcard covers exactly one label, which must be non-empty.
			if hl == "" {
				return false
			}
			continue
		}
		if pl != hl {
			return false
		}
	}
	return true
}

// CertNameMatchesPattern matches a certificate identity (which may itself be a
// wildcard) against a policy pattern (which may also be a wildcard).
func CertNameMatchesPattern(certName, pattern string) bool {
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

// ValidMXPattern reports whether s is an mx pattern RFC 8461 §3.2 allows:
// ["*."] Domain, where Domain is an RFC 5321 domain name. A trailing root dot
// is read as the absolute form of the same name, as MatchesMX reads it.
func ValidMXPattern(s string) bool {
	return ValidDomain(strings.TrimPrefix(s, "*."))
}

// ValidDomain reports whether s is an RFC 5321 §4.1.2 Domain: dot-separated
// labels of letters, digits and hyphens, each starting and ending with a
// letter or digit, at most 63 octets each and 253 in all, optionally followed
// by one root dot. Non-ASCII (a U-label) is refused: RFC 8461 wants A-labels.
func ValidDomain(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !isAlnum(c) && c != '-' {
				return false
			}
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

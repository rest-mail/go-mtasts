package domainname

import "golang.org/x/net/idna"

// ToASCII returns the normalized A-label form of a domain name that may carry
// U-labels (RFC 5890 §2.3.2.1), and whether it is a valid DNS name. RFC 8461
// names the Policy Domain, the _mta-sts TXT name and the policy host in
// A-labels, so a recipient domain taken from an SMTPUTF8 address (RFC 6531)
// must be converted before it is looked up.
//
// An all-ASCII name is only normalized, never passed through IDNA, so its
// validity is exactly ValidDomain's. A name holding non-ASCII is converted
// with UTS #46 lookup processing, non-transitional, as IDNA2008 asks (RFC
// 5891 §5), and refused when it has no valid A-label form.
func ToASCII(s string) (string, bool) {
	s = NormalizeHost(s)
	if !isASCII(s) {
		a, err := idna.Lookup.ToASCII(s)
		if err != nil {
			return s, false
		}
		s = NormalizeHost(a)
	}
	return s, ValidDomain(s)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

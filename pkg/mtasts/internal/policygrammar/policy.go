package policygrammar

import (
	"fmt"
	"math"
	"strings"

	"github.com/rest-mail/go-mtasts/pkg/mtasts/internal/domainname"
)

// Policy modes (RFC 8461 section 5).
const (
	modeEnforce = "enforce"
	modeTesting = "testing"
	modeNone    = "none"
)

// version is the only MTA-STS policy version defined by RFC 8461.
const version = "STSv1"

// MaxAgeLimit is the largest max_age RFC 8461 §3.2 permits: a non-negative
// integer number of seconds of at most ten digits, no larger than 31557600
// (~1 year). A value outside that range makes the policy invalid rather than
// yielding a bogus cache TTL.
const MaxAgeLimit = 31557600

// Policy is a parsed MTA-STS policy file.
type Policy struct {
	Version string   // always "STSv1"
	Mode    string   // "enforce", "testing", or "none"
	MX      []string // MX host patterns; may use a single leading-label wildcard, e.g. "*.example.com"
	MaxAge  int      // policy lifetime in seconds
}

// Parse parses the RFC 8461 section 3.2 policy-file grammar.
func Parse(body []byte) (*Policy, error) {
	p := &Policy{}
	// RFC 8461 section 3.2: for any non-repeated field — every field except
	// "mx" — "all entries except for the first SHALL be ignored." We track the
	// first occurrence of each single-valued key and drop later duplicates,
	// including a later invalid max_age (which must not reject the policy).
	// last-wins would let a trailing injected line silently change enforcement.
	var sawVersion, sawMode, sawMaxAge bool
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
			if sawVersion {
				continue
			}
			p.Version = value
			sawVersion = true
		case "mode":
			if sawMode {
				continue
			}
			p.Mode = value
			sawMode = true
		case "mx":
			// RFC 8461 §3.2: sts-policy-mx-value = ["*."] Domain, and an
			// internationalized name MUST be given as its A-label. A pattern
			// that is not one cannot be matched as the publisher meant, so the
			// policy is invalid rather than enforced with a pattern missing.
			if !domainname.ValidMXPattern(value) {
				return nil, fmt.Errorf("mtasts: invalid mx pattern %q", value)
			}
			p.MX = append(p.MX, value)
		case "max_age":
			if sawMaxAge {
				continue
			}
			// sts-policy-max-age-value = 1*10(DIGIT).
			n, err := parseUint(value)
			if err == nil && len(value) > 10 {
				err = fmt.Errorf("more than 10 digits")
			}
			if err != nil {
				return nil, fmt.Errorf("mtasts: invalid max_age %q: %w", value, err)
			}
			p.MaxAge = n
			sawMaxAge = true
		}
	}

	if p.Version != version {
		return nil, fmt.Errorf("mtasts: unsupported version %q", p.Version)
	}
	switch p.Mode {
	case modeEnforce, modeTesting, modeNone:
	default:
		return nil, fmt.Errorf("mtasts: invalid mode %q", p.Mode)
	}
	if !sawMaxAge {
		return nil, fmt.Errorf("mtasts: missing max_age")
	}
	// RFC 8461 §3.2: max_age is a non-negative integer, at most 31557600. A
	// larger value makes the policy invalid; accepting it would produce a wildly
	// wrong cache TTL. Zero is valid: the policy applies now and is not cached.
	if p.MaxAge > MaxAgeLimit {
		return nil, fmt.Errorf("mtasts: max_age %d out of range (RFC 8461 §3.2 allows 0..%d)", p.MaxAge, MaxAgeLimit)
	}
	if p.Mode != modeNone && len(p.MX) == 0 {
		return nil, fmt.Errorf("mtasts: mode %q requires at least one mx", p.Mode)
	}
	return p, nil
}

// parseUint parses a non-negative base-10 integer, rejecting empty input, stray
// non-digit characters (fmt.Sscanf would silently accept "123abc"), and values
// that overflow int. The unbounded accumulator would otherwise wrap to a
// negative or bogus number — the root of the negative cache-TTL bug in issue #7
// where a huge max_age silently produced an already-expired policy.
func parseUint(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	const cutoff = math.MaxInt / 10
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("non-digit %q", r)
		}
		if n > cutoff {
			return 0, fmt.Errorf("value overflows int")
		}
		n *= 10
		d := int(r - '0')
		if n > math.MaxInt-d {
			return 0, fmt.Errorf("value overflows int")
		}
		n += d
	}
	return n, nil
}

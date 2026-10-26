package domainname

import (
	"strings"
	"testing"

	foxmtasts "github.com/foxcpp/go-mtasts"
)

// FuzzMatchesMX matches any host against any pattern: matching never panics,
// ignores case and a trailing dot, requires the same number of labels, and a
// wildcard pattern matches only hosts with one more label than its base. Where
// diffComparable says they should, the result agrees with go-mtasts.
//
// checklist: MTASTS-MX-02 MTASTS-MX-03
func FuzzMatchesMX(f *testing.F) {
	for _, seed := range [][2]string{
		{"*.example.net", "mx1.example.net"},
		{"*.example.net", "example.net"},
		{"*.example.net", "a.b.example.net"},
		{"mail.example.com.", "MAIL.example.COM"},
		{"*", "x"},
		{"*.", "."},
		{"..", "*.*"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, pattern, host string) {
		patterns := []string{pattern}
		got := MatchesMX(patterns, host)
		if diffComparable(pattern, host) {
			if theirs := (foxmtasts.Policy{MX: []string{pattern}}).Match(host); got != theirs {
				t.Fatalf("pattern %q, host %q: MatchesMX = %v, go-mtasts = %v", pattern, host, got, theirs)
			}
		}
		if isASCII(host) && !strings.HasSuffix(host, ".") && got != MatchesMX(patterns, strings.ToUpper(host)+".") {
			t.Fatalf("pattern %q: %q and its upper-case absolute form disagree", pattern, host)
		}
		if !got {
			return
		}
		h, pat := NormalizeHost(host), NormalizeHost(pattern)
		if !ValidDomain(h) {
			t.Fatalf("pattern %q matched %q, which is not a DNS name", pattern, host)
		}
		if strings.Count(h, ".") != strings.Count(pat, ".") {
			t.Fatalf("pattern %q matched %q with a different number of labels", pattern, host)
		}
		if base, ok := strings.CutPrefix(pat, "*."); ok {
			if !strings.HasSuffix(h, "."+base) || strings.Contains(strings.TrimSuffix(h, "."+base), ".") {
				t.Fatalf("pattern %q matched %q", pattern, host)
			}
		} else if h != pat {
			t.Fatalf("pattern %q matched %q", pattern, host)
		}
	})
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

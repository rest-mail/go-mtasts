package mtasts

import (
	"slices"
	"strings"
	"testing"

	foxmtasts "github.com/foxcpp/go-mtasts"
)

// FuzzParsePolicy parses any policy body: the parser never panics, and a
// policy it accepts is STSv1 with a defined mode, a max_age in range, valid mx
// patterns, and at least one of them unless the mode is "none". Parsing the
// accepted policy written out again gives the same policy.
//
// checklist: MTASTS-POL-03 MTASTS-POL-06 MTASTS-POL-08
func FuzzParsePolicy(f *testing.F) {
	for _, seed := range []string{
		rfc8461Policy,
		testPolicyBody,
		"version: STSv1\nmode: none\nmax_age: 0\n",
		"version: STSv1\nversion: STSv2\nmode: testing\nmode: none\nmx: *.example.net\nmax_age: 31557600\nmax_age: x\n",
		"version:STSv1\r\nmode:\tenforce\r\nmx:xn--bcher-kva.example.\r\nmax_age:0000086400",
		"version: STSv1\nmode: enforce\nmx: a..b\nmax_age: 99999999999\n",
		":\n::\nmx:\n\x00",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		p, err := ParsePolicy(body)
		if err != nil {
			return
		}
		if p.Version != Version || !slices.Contains([]string{ModeEnforce, ModeTesting, ModeNone}, p.Mode) ||
			p.MaxAge < 0 || p.MaxAge > maxMaxAge || p.Mode != ModeNone && len(p.MX) == 0 {
			t.Fatalf("accepted an invalid policy %+v", p)
		}
		var b strings.Builder
		b.WriteString("version: " + p.Version + "\nmode: " + p.Mode + "\n")
		for _, mx := range p.MX {
			if !validMXPattern(mx) {
				t.Fatalf("accepted mx %q", mx)
			}
			b.WriteString("mx: " + mx + "\n")
		}
		b.WriteString("max_age: " + itoa(p.MaxAge) + "\n")
		again, err := ParsePolicy([]byte(b.String()))
		if err != nil || again.Mode != p.Mode || again.MaxAge != p.MaxAge || !slices.Equal(again.MX, p.MX) {
			t.Fatalf("%+v written out parses as (%+v, %v)", p, again, err)
		}
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}

// FuzzParseTXTRecord parses any TXT record: the parser never panics, and an id
// it accepts is 1 to 32 letters and digits from a record that begins with
// "v=STSv1" and holds only US-ASCII.
//
// checklist: MTASTS-TXT-03
func FuzzParseTXTRecord(f *testing.F) {
	for _, seed := range []string{
		"v=STSv1; id=20160831085700Z;",
		"v=STSv1;id=a;ext=b;",
		"v=STSv1 ; id=abc ; a.b_c-d=!~",
		"v=STSv1; id=abc; id=def",
		"v=STSv1; id=; =;;",
		"v=STSv1\x00; id=a",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, rec string) {
		id, ok := parseTXTID([]string{rec})
		if !ok {
			if id != "" {
				t.Fatalf("rejected record returned id %q", id)
			}
			return
		}
		if !validSTSID(id) || !strings.HasPrefix(rec, "v="+Version) || !strings.Contains(rec, "id="+id) {
			t.Fatalf("accepted id %q from %q", id, rec)
		}
		for i := 0; i < len(rec); i++ {
			if rec[i] > 0x7e || rec[i] < 0x20 && rec[i] != '\t' {
				t.Fatalf("accepted a record with byte %#x", rec[i])
			}
		}
	})
}

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
		p := &Policy{MX: []string{pattern}}
		got := p.MatchesMX(host)
		if diffComparable(pattern, host) {
			if theirs := (foxmtasts.Policy{MX: []string{pattern}}).Match(host); got != theirs {
				t.Fatalf("pattern %q, host %q: MatchesMX = %v, go-mtasts = %v", pattern, host, got, theirs)
			}
		}
		if isASCII(host) && !strings.HasSuffix(host, ".") && got != p.MatchesMX(strings.ToUpper(host)+".") {
			t.Fatalf("pattern %q: %q and its upper-case absolute form disagree", pattern, host)
		}
		if !got {
			return
		}
		h, pat := normalizeHost(host), normalizeHost(pattern)
		if !validDomain(h) {
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

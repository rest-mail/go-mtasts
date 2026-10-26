package txtrecord

import (
	"strings"
	"testing"
)

// checklist: MTASTS-TXT-02 MTASTS-TXT-04 MTASTS-TXT-07
func TestParseTXTID(t *testing.T) {
	cases := []struct {
		name    string
		records []string
		wantID  string
		wantOK  bool
	}{
		{"single valid", []string{"v=STSv1; id=20230101Z"}, "20230101Z", true},
		{"no space after delim", []string{"v=STSv1;id=xyz"}, "xyz", true},
		{"whitespace around delim", []string{"v=STSv1 ; id=xyz"}, "xyz", true},
		{"ignores non-sts records", []string{"v=spf1 -all", "v=STSv1; id=aaa"}, "aaa", true},
		{"trailing extension ignored", []string{"v=STSv1; id=aaa; foo=bar"}, "aaa", true},
		{"missing id", []string{"v=STSv1;"}, "", false},
		{"two sts records is ambiguous", []string{"v=STSv1; id=a", "v=STSv1; id=b"}, "", false},
		{"none", []string{"v=spf1 -all"}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, ok := ID(c.records)
			if ok != c.wantOK || id != c.wantID {
				t.Fatalf("ID(%v) = (%q,%v), want (%q,%v)", c.records, id, ok, c.wantID, c.wantOK)
			}
		})
	}
}

// TestParseTXTIDStrict is the red-green guard for issue #11: the _mta-sts TXT
// record parser must reject records that do not conform to the RFC 8461 §3.1
// grammar. On the pre-fix (lenient) parser every case below is ACCEPTED, which
// lets a malformed or attacker-shaped discovery record drive policy
// discovery/caching. Each must now be treated as "no policy" (ok == false).
//
// checklist: MTASTS-TXT-02 MTASTS-TXT-03
func TestParseTXTIDStrict(t *testing.T) {
	longID := strings.Repeat("a", 33) // 33 > the 32-char id cap

	reject := []struct {
		name    string
		records []string
	}{
		{"version not first (fields out of order)", []string{"id=abc; v=STSv1"}},
		{"whitespace inside version field", []string{"v = STSv1; id=xyz"}},
		{"whitespace around id equals", []string{"v=STSv1; id = xyz"}},
		{"wrong version value", []string{"v=STSv2; id=xyz"}},
		{"id charset: underscore", []string{"v=STSv1; id=abc_def"}},
		{"id charset: dot", []string{"v=STSv1; id=abc.def"}},
		{"id charset: hyphen", []string{"v=STSv1; id=abc-def"}},
		{"id too long (>32)", []string{"v=STSv1; id=" + longID}},
		{"empty id value", []string{"v=STSv1; id="}},
		{"junk record", []string{"totally bogus"}},
	}
	for _, c := range reject {
		t.Run(c.name, func(t *testing.T) {
			if id, ok := ID(c.records); ok {
				t.Fatalf("ID(%v) accepted a malformed record (id=%q); RFC 8461 §3.1 requires rejection", c.records, id)
			}
		})
	}

	// The id boundary: exactly 32 alphanumeric chars is the longest valid id.
	t.Run("id exactly 32 chars accepted", func(t *testing.T) {
		id := strings.Repeat("a", 32)
		got, ok := ID([]string{"v=STSv1; id=" + id})
		if !ok || got != id {
			t.Fatalf("ID 32-char id = (%q,%v), want (%q,true)", got, ok, id)
		}
	})
}

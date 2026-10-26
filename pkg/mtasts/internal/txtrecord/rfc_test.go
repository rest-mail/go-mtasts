package txtrecord

import (
	"strings"
	"testing"
)

// TestTXTRecordGrammar checks the TXT record against the sts-text-record ABNF,
// extension fields included.
//
// checklist: MTASTS-TXT-03 MTASTS-TXT-07
func TestTXTRecordGrammar(t *testing.T) {
	for rec, want := range map[string]string{
		"v=STSv1;id=abc":                                     "abc",
		"v=STSv1; id=abc;":                                   "abc",
		"v=STSv1 ;\tid=abc\t; ":                              "abc",
		"v=STSv1; ext=val; id=abc":                           "abc",
		"v=STSv1; id=abc; a.b_c-d=!\"#$%&'<>":                "abc",
		"v=STSv1; id=abc; " + strings.Repeat("e", 32) + "=1": "abc",
	} {
		if id, ok := ID([]string{rec}); !ok || id != want {
			t.Errorf("ID(%q) = (%q, %v), want (%q, true)", rec, id, ok, want)
		}
	}
	if id, ok := parseSTSTextRecord("id=abc; v=STSv1"); ok {
		t.Errorf("parseSTSTextRecord accepted a record not led by v=STSv1, id %q", id)
	}
	for _, rec := range []string{
		"v=STSv1",
		"v=STSv1;",
		" v=STSv1; id=abc",
		"v=STSv1; id=abc;;",
		"v=STSv1; id=abc; =val",
		"v=STSv1; id=abc; ext=",
		"v=STSv1; id=abc; ext",
		"v=STSv1; id=abc; ext=a=b",
		"v=STSv1; id=abc; _ext=val",
		"v=STSv1; id=abc; ext!=val",
		"v=STSv1; id=abc; " + strings.Repeat("e", 33) + "=1",
		"v=STSv1; id=abc; ext=café",
		"v=STSv1; id=abc; ext=a\x7f",
		"v=STSv1; id=abc ext=val",
		"v=STSv1; id=abc\r\n",
		"v=STSv1; ID=abc",
	} {
		if id, ok := ID([]string{rec}); ok {
			t.Errorf("ID(%q) accepted id %q", rec, id)
		}
	}
}

// TestTXTRecordDiscardRule checks the rule for several TXT records: those not
// beginning "v=STSv1;" are dropped, and exactly one valid record must remain.
//
// checklist: MTASTS-TXT-04
func TestTXTRecordDiscardRule(t *testing.T) {
	cases := []struct {
		name    string
		records []string
		wantID  string
		wantOK  bool
	}{
		{"other versions dropped", []string{"v=STSv10; id=x", "v=STSv1; id=a", "V=STSV1; id=y"}, "a", true},
		{"prefix without delimiter dropped", []string{"v=STSv1id=x", "v=STSv1; id=a"}, "a", true},
		{"spf and junk dropped", []string{"v=spf1 -all", "", "id=x", "v=STSv1; id=a"}, "a", true},
		{"two remain", []string{"v=STSv1; id=a", "v=STSv1; id=a"}, "", false},
		{"two remain, one invalid", []string{"v=STSv1; id=a", "v=STSv1; id=!"}, "", false},
		{"one remains, invalid", []string{"v=STSv1; id=!", "v=spf1 -all"}, "", false},
		{"none remain", []string{"v=STSv2; id=a"}, "", false},
		{"no records", nil, "", false},
	}
	for _, c := range cases {
		id, ok := ID(c.records)
		if id != c.wantID || ok != c.wantOK {
			t.Errorf("%s: ID = (%q, %v), want (%q, %v)", c.name, id, ok, c.wantID, c.wantOK)
		}
	}
}

// TestTXTRecordFirstWins checks that a repeated v= or id= field is ignored
// after its first occurrence.
//
// checklist: MTASTS-TXT-08
func TestTXTRecordFirstWins(t *testing.T) {
	for rec, want := range map[string]string{
		"v=STSv1; id=abc; id=def":   "abc",
		"v=STSv1; v=STSv1; id=abc":  "abc",
		"v=STSv1; id=abc; v=STSv2":  "abc",
		"v=STSv1; id=abc; id=d.e.f": "abc",
	} {
		if id, ok := ID([]string{rec}); !ok || id != want {
			t.Errorf("ID(%q) = (%q, %v), want (%q, true)", rec, id, ok, want)
		}
	}
}

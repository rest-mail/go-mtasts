package txtrecord

import (
	"strings"
	"testing"
)

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
		id, ok := ID([]string{rec})
		if !ok {
			if id != "" {
				t.Fatalf("rejected record returned id %q", id)
			}
			return
		}
		if !validSTSID(id) || !strings.HasPrefix(rec, "v="+version) || !strings.Contains(rec, "id="+id) {
			t.Fatalf("accepted id %q from %q", id, rec)
		}
		for i := 0; i < len(rec); i++ {
			if rec[i] > 0x7e || rec[i] < 0x20 && rec[i] != '\t' {
				t.Fatalf("accepted a record with byte %#x", rec[i])
			}
		}
	})
}

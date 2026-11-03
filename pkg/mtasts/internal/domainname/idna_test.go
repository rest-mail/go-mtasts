package domainname

import "testing"

// TestToASCII checks U-label to A-label conversion, and that a name with no
// valid A-label form is refused, so it never reaches a lookup.
//
// checklist: MTASTS-DOM-03
func TestToASCII(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"bücher.example", "xn--bcher-kva.example", true},
		{"BÜCHER.Example.", "xn--bcher-kva.example", true},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", true},
		{"Example.COM.", "example.com", true},
		{"mail.bücher.example", "mail.xn--bcher-kva.example", true},
		{"例え.テスト", "xn--r8jz45g.xn--zckzah", true},
		// Non-transitional processing keeps ß and ς (IDNA2008).
		{"faß.example", "xn--fa-hia.example", true},
		{"", "", false},
		{"bü/cher.example", "", false},
		{"bü cher.example", "", false},
		{"bücher..example", "", false},
		{"-bücher.example", "", false},
		{"bücher@example", "", false},
	}
	for _, c := range cases {
		got, ok := ToASCII(c.in)
		if ok != c.ok || (c.ok && got != c.want) {
			t.Errorf("ToASCII(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

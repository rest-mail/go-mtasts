package policygrammar

import (
	"slices"
	"strings"
	"testing"

	"github.com/rest-mail/go-mtasts/pkg/mtasts/internal/domainname"
)

const rfc8461Policy = "version: STSv1\r\n" +
	"mode: enforce\r\n" +
	"mx: mail.example.com\r\n" +
	"mx: *.example.net\r\n" +
	"mx: backupmx.example.com\r\n" +
	"max_age: 604800\r\n"

const testPolicyBody = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"

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
		p, err := Parse(body)
		if err != nil {
			return
		}
		if p.Version != version || !slices.Contains([]string{modeEnforce, modeTesting, modeNone}, p.Mode) ||
			p.MaxAge < 0 || p.MaxAge > MaxAgeLimit || p.Mode != modeNone && len(p.MX) == 0 {
			t.Fatalf("accepted an invalid policy %+v", p)
		}
		var b strings.Builder
		b.WriteString("version: " + p.Version + "\nmode: " + p.Mode + "\n")
		for _, mx := range p.MX {
			if !domainname.ValidMXPattern(mx) {
				t.Fatalf("accepted mx %q", mx)
			}
			b.WriteString("mx: " + mx + "\n")
		}
		b.WriteString("max_age: " + itoa(p.MaxAge) + "\n")
		again, err := Parse([]byte(b.String()))
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

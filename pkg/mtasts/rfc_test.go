package mtasts

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// rfc8461Policy is the example policy of RFC 8461 §3.2 and Appendix A.
const rfc8461Policy = "version: STSv1\r\n" +
	"mode: enforce\r\n" +
	"mx: mail.example.com\r\n" +
	"mx: *.example.net\r\n" +
	"mx: backupmx.example.com\r\n" +
	"max_age: 604800\r\n"

// TestRFC8461Section32Example parses the example policy of §3.2 as published,
// with CRLF line ends.
//
// checklist: MTASTS-POL-12
func TestRFC8461Section32Example(t *testing.T) {
	p, err := ParsePolicy([]byte(rfc8461Policy))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	want := &Policy{Version: Version, Mode: ModeEnforce, MX: []string{"mail.example.com", "*.example.net", "backupmx.example.com"}, MaxAge: 604800}
	if p.Version != want.Version || p.Mode != want.Mode || p.MaxAge != want.MaxAge || !slices.Equal(p.MX, want.MX) {
		t.Errorf("ParsePolicy = %+v, want %+v", p, want)
	}
}

// TestRFC8461AppendixA runs discovery for the example of Appendix A: the TXT
// record and the policy it points to.
//
// checklist: MTASTS-TXT-01 MTASTS-POL-01 MTASTS-POL-12
func TestRFC8461AppendixA(t *testing.T) {
	f := newFakeResolver()
	f.txt["_mta-sts.example.com"] = []string{"v=STSv1; id=20160831085700Z;"}
	f.policies["https://mta-sts.example.com/.well-known/mta-sts.txt"] = rfc8461Policy
	p, err := f.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Mode != ModeEnforce || p.MaxAge != 604800 || len(p.MX) != 3 {
		t.Fatalf("Resolve = %+v", p)
	}
	for host, want := range map[string]bool{
		"mail.example.com":     true,
		"backupmx.example.com": true,
		"mx1.example.net":      true,
		"example.net":          false,
		"a.b.example.net":      false,
		"other.example.com":    false,
	} {
		if got := p.MatchesMX(host); got != want {
			t.Errorf("MatchesMX(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestRFC8461Section41Examples checks the wildcard examples of §4.1.
//
// checklist: MTASTS-MX-03
func TestRFC8461Section41Examples(t *testing.T) {
	p := &Policy{MX: []string{"*.example.com"}}
	for host, want := range map[string]bool{
		"mail.example.com":    true,
		"example.com":         false,
		"foo.bar.example.com": false,
	} {
		if got := p.MatchesMX(host); got != want {
			t.Errorf("MatchesMX(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestMatchesMXEdgeCases covers trailing dots and case on either side, and
// names that only look like a match.
//
// checklist: MTASTS-MX-02
func TestMatchesMXEdgeCases(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"mail.example.com.", "mail.example.com", true},
		{"mail.example.com.", "mail.example.com.", true},
		{"MAIL.Example.COM", "mail.example.com", true},
		{"*.EXAMPLE.net", "MX1.example.NET.", true},
		{"*.example.net.", "mx1.example.net", true},
		{"xn--bcher-kva.example", "XN--BCHER-KVA.example", true},
		{"mail.example.com", "mail.example.com..", false},
		{"mail.example.com", "mail.example.co", false},
		{"mail.example.com", "amail.example.com", false},
		{"*.example.net", "example.net.", false},
		{"*.example.net", "*.example.net", false},
		{"*.example.net", "mx1.example.net.evil", false},
		{"*.example.net", "mx1xexample.net", false},
		{"*.example.net", ".", false},
		{"mail.example.com", " mail.example.com ", false},
		{"*", "localhost", false},
	}
	for _, c := range cases {
		p := &Policy{MX: []string{c.pattern}}
		if got := p.MatchesMX(c.host); got != c.want {
			t.Errorf("pattern %q, host %q: MatchesMX = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

// TestParsePolicyCaseSensitive checks that version and mode values are
// matched exactly.
//
// checklist: MTASTS-POL-04 MTASTS-POL-05
func TestParsePolicyCaseSensitive(t *testing.T) {
	for name, body := range map[string]string{
		"version lower case": "version: stsv1\nmode: enforce\nmx: a.example.com\nmax_age: 86400\n",
		"version upper case": "version: STSV1\nmode: enforce\nmx: a.example.com\nmax_age: 86400\n",
		"mode capitalised":   "version: STSv1\nmode: Enforce\nmx: a.example.com\nmax_age: 86400\n",
		"mode upper case":    "version: STSv1\nmode: TESTING\nmx: a.example.com\nmax_age: 86400\n",
		"version missing":    "mode: enforce\nmx: a.example.com\nmax_age: 86400\n",
		"mode missing":       "version: STSv1\nmx: a.example.com\nmax_age: 86400\n",
	} {
		if p, err := ParsePolicy([]byte(body)); err == nil {
			t.Errorf("%s: ParsePolicy = %+v, want an error", name, p)
		}
	}
}

// TestParsePolicyUnknownFields checks that fields RFC 8461 does not define are
// ignored, and that a policy with them is still valid.
//
// checklist: MTASTS-POL-10
func TestParsePolicyUnknownFields(t *testing.T) {
	body := "version: STSv1\nmode: testing\nx-note: anything at all\nmx: a.example.com\nfuture_field: 1\nmax_age: 86400\n"
	p, err := ParsePolicy([]byte(body))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.Mode != ModeTesting || !slices.Equal(p.MX, []string{"a.example.com"}) || p.MaxAge != 86400 {
		t.Errorf("ParsePolicy = %+v", p)
	}
}

// TestParsePolicyMXPatterns checks the mx pattern grammar: a domain name in
// A-label form, optionally behind "*.".
//
// checklist: MTASTS-POL-08 MTASTS-POL-09
func TestParsePolicyMXPatterns(t *testing.T) {
	policy := func(mx string) string {
		return "version: STSv1\nmode: enforce\nmx: " + mx + "\nmax_age: 86400\n"
	}
	for _, mx := range []string{
		"mail.example.com",
		"*.example.net",
		"mail.example.com.",
		"xn--bcher-kva.example",
		"localhost",
		"a-b.c0.example",
		strings.Repeat("a", 63) + ".example",
	} {
		if _, err := ParsePolicy([]byte(policy(mx))); err != nil {
			t.Errorf("mx %q rejected: %v", mx, err)
		}
	}
	for _, mx := range []string{
		"",
		"*",
		"*.",
		".",
		"bücher.example",
		"mail..example.com",
		".example.com",
		"-mail.example.com",
		"mail-.example.com",
		"mail_1.example.com",
		"mail.example.com:25",
		"*.*.example.com",
		"mail.*.example.com",
		"m*.example.com",
		"mail example.com",
		"[192.0.2.1]",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 127) + "aa",
	} {
		if p, err := ParsePolicy([]byte(policy(mx))); err == nil {
			t.Errorf("mx %q accepted: %+v", mx, p)
		}
	}
}

// TestResolveIDHasNoOrder checks that ids are compared for equality only: a
// change to an id that sorts lower is still a new policy.
//
// checklist: MTASTS-TXT-09
func TestResolveIDHasNoOrder(t *testing.T) {
	f := newFakeResolver()
	url := PolicyURL("example.com")
	for i, id := range []string{"20240101", "20230101", "20240101"} {
		f.txt[TXTName("example.com")] = []string{"v=STSv1; id=" + id}
		f.policies[url] = strings.Replace(testPolicyBody, "86400", "8640"+string(rune('0'+i)), 1)
		p, err := f.Resolve(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("id %s: %v", id, err)
		}
		if want := 86400 + i; p.MaxAge != want {
			t.Errorf("id %s: MaxAge = %d, want %d (the policy was not fetched again)", id, p.MaxAge, want)
		}
	}
	if f.fetchCount != 3 {
		t.Errorf("fetches = %d, want 3", f.fetchCount)
	}
}

// TestResolveMaxAgeZero checks that a max_age of 0 applies the policy now but
// does not cache it.
//
// checklist: MTASTS-CACHE-01
func TestResolveMaxAgeZero(t *testing.T) {
	f := newFakeResolver()
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=a"}
	f.policies[PolicyURL("example.com")] = strings.Replace(testPolicyBody, "86400", "0", 1)
	for i := range 2 {
		p, err := f.Resolve(context.Background(), "example.com")
		if err != nil || p.Mode != ModeEnforce {
			t.Fatalf("Resolve %d = (%+v, %v)", i, p, err)
		}
	}
	if f.fetchCount != 2 {
		t.Errorf("fetches = %d, want 2: a max_age 0 policy was cached", f.fetchCount)
	}
	f.fetchErr = errors.New("down")
	if p, err := f.Resolve(context.Background(), "example.com"); !errors.Is(err, ErrNoPolicy) {
		t.Errorf("after a failed fetch, Resolve = (%+v, %v), want ErrNoPolicy", p, err)
	}
}

// TestResolveRefreshesDaily checks that a cached policy whose id is unchanged
// is fetched again once a day, long before a long max_age runs out, and stays
// in force when that refresh fails.
//
// checklist: MTASTS-FETCH-12
func TestResolveRefreshesDaily(t *testing.T) {
	f := newFakeResolver()
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=a"}
	f.policies[PolicyURL("example.com")] = strings.Replace(testPolicyBody, "86400", "31557600", 1)
	ctx := context.Background()
	if _, err := f.Resolve(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(24*time.Hour - time.Second)
	if _, err := f.Resolve(ctx, "example.com"); err != nil || f.fetchCount != 1 {
		t.Fatalf("within a day: err %v, fetches %d; want the cached policy and 1 fetch", err, f.fetchCount)
	}
	f.now = f.now.Add(time.Second)
	if _, err := f.Resolve(ctx, "example.com"); err != nil || f.fetchCount != 2 {
		t.Fatalf("after a day: err %v, fetches %d; want a refresh (2 fetches)", err, f.fetchCount)
	}
	f.now = f.now.Add(24 * time.Hour)
	f.fetchErr = errors.New("policy host down")
	p, err := f.Resolve(ctx, "example.com")
	if err != nil || p.Mode != ModeEnforce || f.fetchCount != 3 {
		t.Fatalf("failed refresh: (%+v, %v), fetches %d; want the cached policy after a third fetch", p, err, f.fetchCount)
	}
}

// TestResolveRefreshFailed checks that RefreshFailed hears of every failed
// discovery that leaves a cached policy in force, except for mode "none".
//
// checklist: MTASTS-FETCH-13
func TestResolveRefreshFailed(t *testing.T) {
	type call struct {
		domain string
		mode   string
		err    error
	}
	setup := func(policy string) (*fakeResolver, *[]call) {
		f := newFakeResolver()
		var calls []call
		f.RefreshFailed = func(domain string, cached *Policy, err error) {
			calls = append(calls, call{domain, cached.Mode, err})
		}
		f.txt[TXTName("example.com")] = []string{"v=STSv1; id=a"}
		f.policies[PolicyURL("example.com")] = policy
		if _, err := f.Resolve(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
		return f, &calls
	}
	ctx := context.Background()

	t.Run("TXT lookup error", func(t *testing.T) {
		f, calls := setup(testPolicyBody)
		f.txtErr = errors.New("SERVFAIL")
		if _, err := f.Resolve(ctx, "Example.com"); err != nil {
			t.Fatal(err)
		}
		if len(*calls) != 1 || (*calls)[0].domain != "example.com" || (*calls)[0].mode != ModeEnforce || (*calls)[0].err != f.txtErr {
			t.Errorf("calls = %+v", *calls)
		}
	})
	t.Run("no valid TXT record", func(t *testing.T) {
		f, calls := setup(testPolicyBody)
		f.txt[TXTName("example.com")] = []string{"v=STSv1; id=!"}
		if _, err := f.Resolve(ctx, "example.com"); err != nil {
			t.Fatal(err)
		}
		if len(*calls) != 1 || !errors.Is((*calls)[0].err, ErrNoRecord) {
			t.Errorf("calls = %+v", *calls)
		}
	})
	t.Run("fetch and parse errors, then a suppressed retry", func(t *testing.T) {
		f, calls := setup(testPolicyBody)
		f.txt[TXTName("example.com")] = []string{"v=STSv1; id=b"}
		f.fetchErr = errors.New("connection refused")
		if _, err := f.Resolve(ctx, "example.com"); err != nil {
			t.Fatal(err)
		}
		// The retry inside the negative-cache window makes no attempt, so
		// there is no new failure to report.
		if _, err := f.Resolve(ctx, "example.com"); err != nil {
			t.Fatal(err)
		}
		fetchErr := f.fetchErr
		f.fetchErr = nil
		f.txt[TXTName("example.com")] = []string{"v=STSv1; id=c"}
		f.policies[PolicyURL("example.com")] = "not a policy"
		if _, err := f.Resolve(ctx, "example.com"); err != nil {
			t.Fatal(err)
		}
		if len(*calls) != 2 || !errors.Is((*calls)[0].err, fetchErr) || !errors.Is((*calls)[0].err, ErrPolicyFetch) ||
			!errors.Is((*calls)[1].err, ErrPolicyInvalid) || errors.Is((*calls)[1].err, fetchErr) {
			t.Errorf("calls = %+v, want the fetch error then a parse error", *calls)
		}
	})
	t.Run("mode none is not reported", func(t *testing.T) {
		f, calls := setup("version: STSv1\nmode: none\nmax_age: 86400\n")
		f.txtErr = errors.New("SERVFAIL")
		if _, err := f.Resolve(ctx, "example.com"); err != nil {
			t.Fatal(err)
		}
		if len(*calls) != 0 {
			t.Errorf("calls = %+v, want none", *calls)
		}
	})
	t.Run("nothing cached is not reported", func(t *testing.T) {
		f := newFakeResolver()
		called := false
		f.RefreshFailed = func(string, *Policy, error) { called = true }
		f.txtErr = errors.New("SERVFAIL")
		if _, err := f.Resolve(ctx, "example.com"); !errors.Is(err, ErrNoPolicy) {
			t.Fatalf("Resolve error = %v, want ErrNoPolicy", err)
		}
		if called {
			t.Error("RefreshFailed called with nothing cached")
		}
	})
}

// TestResolveNoParentZone checks that a subdomain without a policy of its own
// does not inherit its parent's.
//
// checklist: MTASTS-DOM-02
func TestResolveNoParentZone(t *testing.T) {
	f := newFakeResolver()
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=a"}
	f.policies[PolicyURL("example.com")] = testPolicyBody
	var looked []string
	lookup := f.LookupTXT
	f.LookupTXT = func(ctx context.Context, name string) ([]string, error) {
		looked = append(looked, name)
		return lookup(ctx, name)
	}
	if p, err := f.Resolve(context.Background(), "sub.example.com"); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("Resolve(sub.example.com) = (%+v, %v), want ErrNoPolicy", p, err)
	}
	if !slices.Equal(looked, []string{"_mta-sts.sub.example.com"}) || f.fetchCount != 0 {
		t.Errorf("looked up %v and fetched %d times; want only _mta-sts.sub.example.com and no fetch", looked, f.fetchCount)
	}
}

// TestResolveRejectsNonDomain checks that a recipient domain that is not a DNS
// name, such as an address literal, has no policy and causes no lookup.
//
// checklist: MTASTS-DOM-03
func TestResolveRejectsNonDomain(t *testing.T) {
	f := newFakeResolver()
	lookups := 0
	f.LookupTXT = func(context.Context, string) ([]string, error) {
		lookups++
		return []string{"v=STSv1; id=a"}, nil
	}
	for _, domain := range []string{
		"",
		".",
		"[192.0.2.1]",
		"[IPv6:2001:db8::1]",
		"example.com/evil",
		"evil.example@example.com",
		"example.com:8443",
		"exa mple.com",
		"example..com",
		"bücher.example",
	} {
		if p, err := f.Resolve(context.Background(), domain); !errors.Is(err, ErrNoPolicy) {
			t.Errorf("Resolve(%q) = (%+v, %v), want ErrNoPolicy", domain, p, err)
		}
	}
	if lookups != 0 || f.fetchCount != 0 {
		t.Errorf("%d lookups and %d fetches, want none", lookups, f.fetchCount)
	}
}

// TestEnforceErrorIsTransient checks that every enforce failure says it is
// temporary, so a queue defers the message rather than bouncing it.
//
// checklist: MTASTS-APPLY-04
func TestEnforceErrorIsTransient(t *testing.T) {
	policy := &Policy{Mode: ModeEnforce, MX: []string{"mail.example.com"}}
	for _, in := range []EvalInput{
		{Policy: policy, MXHost: "other.example.com", STARTTLS: true, CertValid: true},
		{Policy: policy, MXHost: "mail.example.com", STARTTLS: false},
		{Policy: policy, MXHost: "mail.example.com", STARTTLS: true, CertValid: false},
	} {
		err := Evaluate(in)
		var temp interface{ Temporary() bool }
		if !errors.As(err, &temp) || !temp.Temporary() {
			t.Errorf("Evaluate(%+v) = %v, want a temporary error", in, err)
		}
		if msg := err.Error(); !strings.Contains(msg, in.MXHost) || !strings.HasPrefix(msg, "MTA-STS enforce: ") {
			t.Errorf("Error() = %q", msg)
		}
	}
}

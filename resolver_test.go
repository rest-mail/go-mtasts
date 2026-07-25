package mtasts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeResolver builds a Resolver backed by in-memory TXT and policy data plus a
// controllable clock, and counts fetches so cache behaviour can be asserted.
type fakeResolver struct {
	*Resolver
	txt        map[string][]string
	policies   map[string]string
	txtErr     error
	fetchErr   error
	fetchCount int
	now        time.Time
}

func newFakeResolver() *fakeResolver {
	f := &fakeResolver{
		txt:      map[string][]string{},
		policies: map[string]string{},
		now:      time.Unix(1_700_000_000, 0),
	}
	f.Resolver = &Resolver{
		LookupTXT: func(_ context.Context, name string) ([]string, error) {
			if f.txtErr != nil {
				return nil, f.txtErr
			}
			recs, ok := f.txt[name]
			if !ok {
				return nil, fmt.Errorf("no such host")
			}
			return recs, nil
		},
		FetchPolicy: func(_ context.Context, url string) ([]byte, error) {
			f.fetchCount++
			if f.fetchErr != nil {
				return nil, f.fetchErr
			}
			body, ok := f.policies[url]
			if !ok {
				return nil, fmt.Errorf("404")
			}
			return []byte(body), nil
		},
		Now:   func() time.Time { return f.now },
		cache: map[string]cacheEntry{},
	}
	return f
}

func TestResolveHappyPath(t *testing.T) {
	f := newFakeResolver()
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=20230101000000Z"}
	f.policies[PolicyURL("example.com")] = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"

	p, err := f.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Mode != ModeEnforce || len(p.MX) != 1 || p.MX[0] != "mail.example.com" {
		t.Fatalf("bad policy: %+v", p)
	}
}

func TestResolveCachesUntilMaxAge(t *testing.T) {
	f := newFakeResolver()
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=abc"}
	f.policies[PolicyURL("example.com")] = "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 100\n"

	if _, err := f.Resolve(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	// Second call within max_age must be served from cache (no new fetch).
	f.now = f.now.Add(99 * time.Second)
	if _, err := f.Resolve(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if f.fetchCount != 1 {
		t.Fatalf("expected 1 fetch while cached, got %d", f.fetchCount)
	}

	// After max_age elapses, the policy is re-fetched.
	f.now = f.now.Add(2 * time.Second) // total 101s > max_age
	if _, err := f.Resolve(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if f.fetchCount != 2 {
		t.Fatalf("expected re-fetch after max_age, got %d fetches", f.fetchCount)
	}
}

func TestResolveRefetchesWhenIDChanges(t *testing.T) {
	f := newFakeResolver()
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=v1"}
	f.policies[PolicyURL("example.com")] = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 100000\n"

	if _, err := f.Resolve(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	// id changes before max_age elapses => must re-fetch even though cached.
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=v2"}
	if _, err := f.Resolve(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if f.fetchCount != 2 {
		t.Fatalf("expected re-fetch on id change, got %d fetches", f.fetchCount)
	}
}

func TestResolveFailOpen(t *testing.T) {
	t.Run("no TXT record", func(t *testing.T) {
		f := newFakeResolver()
		if _, err := f.Resolve(context.Background(), "nopolicy.com"); !errors.Is(err, ErrNoPolicy) {
			t.Fatalf("want ErrNoPolicy, got %v", err)
		}
	})

	t.Run("TXT lookup error", func(t *testing.T) {
		f := newFakeResolver()
		f.txtErr = errors.New("dns timeout")
		if _, err := f.Resolve(context.Background(), "example.com"); !errors.Is(err, ErrNoPolicy) {
			t.Fatalf("want ErrNoPolicy, got %v", err)
		}
	})

	t.Run("TXT without STSv1", func(t *testing.T) {
		f := newFakeResolver()
		f.txt[TXTName("example.com")] = []string{"some other txt record"}
		if _, err := f.Resolve(context.Background(), "example.com"); !errors.Is(err, ErrNoPolicy) {
			t.Fatalf("want ErrNoPolicy, got %v", err)
		}
	})

	t.Run("policy fetch fails (fail-open despite TXT)", func(t *testing.T) {
		f := newFakeResolver()
		f.txt[TXTName("example.com")] = []string{"v=STSv1; id=abc"}
		f.fetchErr = errors.New("connection refused")
		if _, err := f.Resolve(context.Background(), "example.com"); !errors.Is(err, ErrNoPolicy) {
			t.Fatalf("want ErrNoPolicy, got %v", err)
		}
	})

	t.Run("unparseable policy", func(t *testing.T) {
		f := newFakeResolver()
		f.txt[TXTName("example.com")] = []string{"v=STSv1; id=abc"}
		f.policies[PolicyURL("example.com")] = "not a policy at all"
		if _, err := f.Resolve(context.Background(), "example.com"); !errors.Is(err, ErrNoPolicy) {
			t.Fatalf("want ErrNoPolicy, got %v", err)
		}
	})
}

// TestResolveRetainsCachedEnforceOnTransientFailure asserts the RFC 8461 §3.1 /
// §3.3 requirement: a valid, non-expired cached enforce policy MUST stay in
// effect when a fresh discovery/fetch transiently fails. Dropping it (returning
// ErrNoPolicy) would downgrade the sender to opportunistic TLS — exactly the
// on-path downgrade the cache exists to prevent (§10.2).
func TestResolveRetainsCachedEnforceOnTransientFailure(t *testing.T) {
	const dom = "example.com"
	const enforcePolicy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 100000\n"

	// warm primes the cache with a valid enforce policy, then returns the
	// resolver ready to have a transient failure injected. now stays well
	// within max_age so the cached entry remains non-expired.
	warm := func(t *testing.T) *fakeResolver {
		t.Helper()
		f := newFakeResolver()
		f.txt[TXTName(dom)] = []string{"v=STSv1; id=v1"}
		f.policies[PolicyURL(dom)] = enforcePolicy
		p, err := f.Resolve(context.Background(), dom)
		if err != nil {
			t.Fatalf("priming resolve failed: %v", err)
		}
		if p.Mode != ModeEnforce {
			t.Fatalf("primed policy mode = %q, want %q", p.Mode, ModeEnforce)
		}
		f.now = f.now.Add(10 * time.Second) // still << max_age
		return f
	}

	assertEnforceServed := func(t *testing.T, f *fakeResolver) {
		t.Helper()
		p, err := f.Resolve(context.Background(), dom)
		if err != nil {
			t.Fatalf("cached enforce policy dropped (fail-open downgrade): %v", err)
		}
		if p == nil || p.Mode != ModeEnforce {
			t.Fatalf("served policy = %+v, want cached enforce policy", p)
		}
	}

	t.Run("TXT lookup error", func(t *testing.T) {
		f := warm(t)
		f.txtErr = errors.New("dns timeout")
		assertEnforceServed(t, f)
	})

	t.Run("TXT record missing STSv1", func(t *testing.T) {
		f := warm(t)
		f.txt[TXTName(dom)] = []string{"some unrelated txt"}
		assertEnforceServed(t, f)
	})

	t.Run("id rolled but fetch fails", func(t *testing.T) {
		f := warm(t)
		f.txt[TXTName(dom)] = []string{"v=STSv1; id=v2"} // roll id -> forces refetch
		f.fetchErr = errors.New("connection refused")
		assertEnforceServed(t, f)
	})

	t.Run("id rolled but refetched policy unparseable", func(t *testing.T) {
		f := warm(t)
		f.txt[TXTName(dom)] = []string{"v=STSv1; id=v2"}
		f.policies[PolicyURL(dom)] = "not a policy at all"
		assertEnforceServed(t, f)
	})

	t.Run("expired cache still fails open", func(t *testing.T) {
		f := warm(t)
		f.now = f.now.Add(200000 * time.Second) // past max_age -> cache expired
		f.txtErr = errors.New("dns timeout")
		if _, err := f.Resolve(context.Background(), dom); !errors.Is(err, ErrNoPolicy) {
			t.Fatalf("want ErrNoPolicy once cache expired, got %v", err)
		}
	})
}

// TestStoreOversizedMaxAgeCachesInsteadOfExpiring is the resolver-side guard for
// issue #7. A policy whose max_age overflows time.Duration when multiplied by a
// second (> 9223372036) must still yield a future expiry — clamped to the cache
// cap — rather than a negative TTL that makes the entry expire immediately and
// forces a re-fetch on every outbound message (defeating the cache-based
// downgrade protection of RFC 8461 §10.2).
func TestStoreOversizedMaxAgeCachesInsteadOfExpiring(t *testing.T) {
	f := newFakeResolver()
	// 9223372037 * 1e9 ns overflows int64, wrapping to a negative Duration on
	// unfixed code.
	policy := &Policy{Version: Version, Mode: ModeEnforce, MX: []string{"mail.example.com"}, MaxAge: 9223372037}
	f.store("example.com", "id1", policy, f.now)

	if got := f.cached("example.com", "id1", f.now); got == nil {
		t.Fatal("oversized max_age produced an already-expired entry (negative TTL); want cached policy")
	}
	// The clamped entry must still be served just shy of the cache cap.
	if got := f.cached("example.com", "id1", f.now.Add(maxCacheTTL-time.Second)); got == nil {
		t.Fatal("entry expired before the cache cap; TTL was not clamped to maxCacheTTL")
	}
}

// TestZeroValueResolverDoesNotPanic asserts that a Resolver built as a literal
// (mtasts.Resolver{}) — rather than via NewResolver — is usable rather than a
// nil-panic trap (issue #14). Before the fix, Resolve dereferenced a nil
// LookupTXT/FetchPolicy field and panicked; the zero value must instead fall
// back to the real-network defaults, exactly as r.now() already falls back to
// time.Now.
//
// The context is pre-cancelled so the fallbacks return promptly without doing
// real network I/O: net.DefaultResolver.LookupTXT and the default HTTPFetch both
// honour the cancelled context and error out, which Resolve maps to ErrNoPolicy.
// The assertion is really "did not panic"; ErrNoPolicy is the well-defined
// fail-open result of that cancelled discovery.
func TestZeroValueResolverDoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("nil LookupTXT falls back to default resolver", func(t *testing.T) {
		var r Resolver // zero value: LookupTXT, FetchPolicy, Now all nil
		if _, err := r.Resolve(ctx, "example.com"); !errors.Is(err, ErrNoPolicy) {
			t.Fatalf("zero-value Resolver: want ErrNoPolicy from cancelled lookup, got %v", err)
		}
	})

	t.Run("nil FetchPolicy falls back to default fetch", func(t *testing.T) {
		// A working TXT lookup advances Resolve to the fetch step, where a nil
		// FetchPolicy would panic before the fix. FetchPolicy is left nil.
		r := Resolver{
			LookupTXT: func(context.Context, string) ([]string, error) {
				return []string{"v=STSv1; id=abc"}, nil
			},
		}
		if _, err := r.Resolve(ctx, "example.com"); !errors.Is(err, ErrNoPolicy) {
			t.Fatalf("nil FetchPolicy: want ErrNoPolicy from cancelled fetch, got %v", err)
		}
	})
}

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
			id, ok := parseTXTID(c.records)
			if ok != c.wantOK || id != c.wantID {
				t.Fatalf("parseTXTID(%v) = (%q,%v), want (%q,%v)", c.records, id, ok, c.wantID, c.wantOK)
			}
		})
	}
}

// TestParseTXTIDStrict is the red-green guard for issue #11: the _mta-sts TXT
// record parser must reject records that do not conform to the RFC 8461 §3.1
// grammar. On the pre-fix (lenient) parser every case below is ACCEPTED, which
// lets a malformed or attacker-shaped discovery record drive policy
// discovery/caching. Each must now be treated as "no policy" (ok == false).
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
		{"duplicate version field", []string{"v=STSv1; v=STSv1; id=abc"}},
		{"duplicate id field", []string{"v=STSv1; id=abc; id=def"}},
		{"junk record", []string{"totally bogus"}},
	}
	for _, c := range reject {
		t.Run(c.name, func(t *testing.T) {
			if id, ok := parseTXTID(c.records); ok {
				t.Fatalf("parseTXTID(%v) accepted a malformed record (id=%q); RFC 8461 §3.1 requires rejection", c.records, id)
			}
		})
	}

	// The id boundary: exactly 32 alphanumeric chars is the longest valid id.
	t.Run("id exactly 32 chars accepted", func(t *testing.T) {
		id := strings.Repeat("a", 32)
		got, ok := parseTXTID([]string{"v=STSv1; id=" + id})
		if !ok || got != id {
			t.Fatalf("parseTXTID 32-char id = (%q,%v), want (%q,true)", got, ok, id)
		}
	})
}

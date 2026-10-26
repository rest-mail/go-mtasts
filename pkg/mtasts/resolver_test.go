package mtasts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
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
		Now: func() time.Time { return f.now },
	}
	return f
}

// checklist: MTASTS-CACHE-02
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

// checklist: MTASTS-CACHE-01 MTASTS-CACHE-02 MTASTS-APPLY-06
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

// checklist: MTASTS-TXT-09 MTASTS-CACHE-02
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

// checklist: MTASTS-FETCH-10
func TestResolveFailOpen(t *testing.T) {
	t.Run("no TXT record", func(t *testing.T) {
		f := newFakeResolver()
		// A fallback without a discovery error still reports the absence of
		// a policy; this path has no failure reason to wrap.
		if p, err := f.cachedOrNoPolicy("nopolicy.com", f.now, nil, false); p != nil || err != ErrNoPolicy {
			t.Fatalf("empty cache without a failure: got (%v, %v), want (nil, ErrNoPolicy)", p, err)
		}
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

// TestResolveSaysWhyThereIsNoPolicy checks that the ErrNoPolicy Resolve
// returns says why there is none, as a TLS-RPT report needs (RFC 8461 §6, RFC
// 8460 §4.3.2.2): no record (no such name, or no valid record) is not a
// failure, while a policy that could not be fetched, or did not parse, is;
// the fetch's own error stays in the chain, and a retry the negative cache
// suppresses gives the same reason.
//
// checklist: MTASTS-REP-01
func TestResolveSaysWhyThereIsNoPolicy(t *testing.T) {
	ctx := context.Background()
	nxdomain := &net.DNSError{Err: "no such host", Name: TXTName("nx.example"), IsNotFound: true}
	for name, tc := range map[string]struct {
		setup func(f *fakeResolver)
		want  error
	}{
		"no such name":    {func(f *fakeResolver) { f.txtErr = nxdomain }, ErrNoRecord},
		"no valid record": {func(f *fakeResolver) { f.txt[TXTName("example.com")] = []string{"v=STSv2; id=1"} }, ErrNoRecord},
		"fetch fails": {func(f *fakeResolver) {
			f.txt[TXTName("example.com")] = []string{"v=STSv1; id=1"}
			f.fetchErr = errors.New("x509: unknown authority")
		}, ErrPolicyFetch},
		"policy not valid": {func(f *fakeResolver) {
			f.txt[TXTName("example.com")] = []string{"v=STSv1; id=1"}
			f.policies[PolicyURL("example.com")] = "mode: sometimes"
		}, ErrPolicyInvalid},
	} {
		f := newFakeResolver()
		tc.setup(f)
		for attempt := 1; attempt <= 2; attempt++ {
			_, err := f.Resolve(ctx, "example.com")
			if !errors.Is(err, ErrNoPolicy) || !errors.Is(err, tc.want) {
				t.Errorf("%s, attempt %d: %v, want ErrNoPolicy and %v", name, attempt, err, tc.want)
			}
			for _, other := range []error{ErrNoRecord, ErrPolicyFetch, ErrPolicyInvalid} {
				if other != tc.want && errors.Is(err, other) {
					t.Errorf("%s: %v is also %v", name, err, other)
				}
			}
		}
		if tc.want == ErrPolicyFetch && f.fetchCount != 1 {
			t.Errorf("%s: fetched %d times, want once (the retry is suppressed)", name, f.fetchCount)
		}
	}
	f := newFakeResolver()
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=1"}
	f.fetchErr = errors.New("x509: certificate signed by unknown authority")
	if _, err := f.Resolve(ctx, "example.com"); !errors.Is(err, f.fetchErr) {
		t.Errorf("the fetch's error is not in the chain: %v", err)
	}
	// A DNS failure that is not a missing name is no record and no failure.
	f = newFakeResolver()
	f.txtErr = errors.New("SERVFAIL")
	if _, err := f.Resolve(ctx, "example.com"); !errors.Is(err, ErrNoPolicy) || errors.Is(err, ErrNoRecord) || errors.Is(err, ErrPolicyFetch) {
		t.Errorf("SERVFAIL: %v", err)
	}
	if _, err := f.Resolve(ctx, "not a domain"); err != ErrNoPolicy {
		t.Errorf("a name that is not a domain: %v", err)
	}
}

// TestResolveRetainsCachedEnforceOnTransientFailure asserts the RFC 8461 §3.1 /
// §3.3 requirement: a valid, non-expired cached enforce policy MUST stay in
// effect when a fresh discovery/fetch transiently fails. Dropping it (returning
// ErrNoPolicy) would downgrade the sender to opportunistic TLS — exactly the
// on-path downgrade the cache exists to prevent (§10.2).
//
// checklist: MTASTS-FETCH-11 MTASTS-CACHE-03 MTASTS-APPLY-06
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

// TestResolveNegativeCachesFailedFetch is the red-green guard for issue #15. A
// failed policy fetch/parse for a given (domain, id) MUST be remembered for a
// bounded interval so repeated Resolve calls within that window do not re-probe
// a broken or blocked policy host on every outbound message (RFC 8461 §3.3, "no
// more than once per five minutes per version id"). On the pre-fix resolver
// every cache-missing Resolve re-fetches, turning any domain whose policy host
// is down or being blocked into an outbound-side amplifier.
//
// checklist: MTASTS-FETCH-08
func TestResolveNegativeCachesFailedFetch(t *testing.T) {
	f := newFakeResolver()
	f.txt[TXTName("broken.example")] = []string{"v=STSv1; id=abc"}
	f.fetchErr = errors.New("connection refused")

	// First Resolve: TXT resolves, the fetch fails -> fail-open ErrNoPolicy, and
	// the failure is negative-cached for the default interval.
	if _, err := f.Resolve(context.Background(), "broken.example"); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("first resolve: want ErrNoPolicy, got %v", err)
	}
	if f.fetchCount != 1 {
		t.Fatalf("first resolve: want 1 fetch, got %d", f.fetchCount)
	}

	// Second Resolve a minute later (well within the ~5-min negative TTL) must be
	// served from the negative cache WITHOUT re-hitting the origin.
	f.now = f.now.Add(1 * time.Minute)
	if _, err := f.Resolve(context.Background(), "broken.example"); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("second resolve: want ErrNoPolicy, got %v", err)
	}
	if f.fetchCount != 1 {
		t.Fatalf("second resolve within the negative-cache TTL must NOT re-fetch; got %d fetches (RFC 8461 §3.3)", f.fetchCount)
	}

	// After the negative TTL lapses, the broken host may be probed once more.
	f.now = f.now.Add(6 * time.Minute) // > 5-min default measured from the first failure
	if _, err := f.Resolve(context.Background(), "broken.example"); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("third resolve: want ErrNoPolicy, got %v", err)
	}
	if f.fetchCount != 2 {
		t.Fatalf("after the negative-cache TTL a single retry is expected; got %d fetches", f.fetchCount)
	}
}

// TestResolveNegativeCacheDoesNotSuppressNewID asserts the "per version id"
// scope of issue #15: a changed TXT id is a new policy and MUST be fetched
// immediately, never suppressed by a negative-cache entry left by the old id.
//
// checklist: MTASTS-FETCH-08
func TestResolveNegativeCacheDoesNotSuppressNewID(t *testing.T) {
	const dom = "broken.example"
	f := newFakeResolver()
	f.txt[TXTName(dom)] = []string{"v=STSv1; id=v1"}
	f.fetchErr = errors.New("connection refused")

	if _, err := f.Resolve(context.Background(), dom); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("priming failed resolve: want ErrNoPolicy, got %v", err)
	}
	if f.fetchCount != 1 {
		t.Fatalf("want 1 fetch, got %d", f.fetchCount)
	}

	// The publisher rotates the id within the negative-cache window and fixes the
	// host. The new id must be fetched immediately, not negative-cached.
	f.now = f.now.Add(1 * time.Minute)
	f.txt[TXTName(dom)] = []string{"v=STSv1; id=v2"}
	f.fetchErr = nil
	f.policies[PolicyURL(dom)] = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 100000\n"

	p, err := f.Resolve(context.Background(), dom)
	if err != nil {
		t.Fatalf("new id must be fetched, not served from the old id's negative cache: %v", err)
	}
	if p == nil || p.Mode != ModeEnforce {
		t.Fatalf("want enforce policy after id rotation, got %+v", p)
	}
	if f.fetchCount != 2 {
		t.Fatalf("a new version id must trigger a fetch; got %d fetches", f.fetchCount)
	}
}

// TestResolveNegativeCacheConcurrent exercises the negative-cache fast path
// under concurrent Resolve calls so the -race detector guards the added map
// accesses. The negative entry is primed with a single failing fetch; every
// concurrent Resolve within the TTL must then short-circuit before FetchPolicy,
// so the fetch count stays at 1 and no goroutine re-probes the origin.
//
// checklist: MTASTS-FETCH-08
func TestResolveNegativeCacheConcurrent(t *testing.T) {
	const dom = "broken.example"
	f := newFakeResolver()
	f.txt[TXTName(dom)] = []string{"v=STSv1; id=abc"}
	f.fetchErr = errors.New("connection refused")

	if _, err := f.Resolve(context.Background(), dom); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("priming failed resolve: want ErrNoPolicy, got %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.Resolve(context.Background(), dom); !errors.Is(err, ErrNoPolicy) {
				t.Errorf("concurrent resolve: want ErrNoPolicy, got %v", err)
			}
		}()
	}
	wg.Wait()

	if f.fetchCount != 1 {
		t.Fatalf("concurrent resolves within the negative-cache TTL must be served without re-fetching; got %d fetches", f.fetchCount)
	}
}

// TestResolveNegativeTTLConfigurable checks that the public NegativeTTL field
// lengthens the suppression window: a fetch still suppressed at the default's
// 6-minute mark proves the caller-set 30-minute TTL is honoured.
//
// checklist: MTASTS-FETCH-08
func TestResolveNegativeTTLConfigurable(t *testing.T) {
	const dom = "broken.example"
	f := newFakeResolver()
	f.NegativeTTL = 30 * time.Minute
	f.txt[TXTName(dom)] = []string{"v=STSv1; id=abc"}
	f.fetchErr = errors.New("connection refused")

	if _, err := f.Resolve(context.Background(), dom); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("first resolve: want ErrNoPolicy, got %v", err)
	}
	if f.fetchCount != 1 {
		t.Fatalf("want 1 fetch, got %d", f.fetchCount)
	}

	// Past the 5-minute default but well within the configured 30-minute TTL:
	// still suppressed, so no second fetch.
	f.now = f.now.Add(6 * time.Minute)
	if _, err := f.Resolve(context.Background(), dom); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("second resolve: want ErrNoPolicy, got %v", err)
	}
	if f.fetchCount != 1 {
		t.Fatalf("NegativeTTL=30m must suppress a re-fetch at 6m; got %d fetches", f.fetchCount)
	}

	// Past the configured TTL: a single retry is allowed.
	f.now = f.now.Add(25 * time.Minute) // 31m from the failure > 30m
	if _, err := f.Resolve(context.Background(), dom); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("third resolve: want ErrNoPolicy, got %v", err)
	}
	if f.fetchCount != 2 {
		t.Fatalf("after the configured TTL a single retry is expected; got %d fetches", f.fetchCount)
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
//
// checklist: MTASTS-FETCH-10
func TestZeroValueResolverDoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("nil LookupTXT falls back to default resolver", func(t *testing.T) {
		var r Resolver // zero value: LookupTXT, FetchPolicy, Now all nil
		if _, err := r.Resolve(ctx, "example.com"); !errors.Is(err, ErrNoPolicy) {
			t.Fatalf("zero-value Resolver: want ErrNoPolicy from cancelled lookup, got %v", err)
		}
	})

	t.Run("NewResolver's fetch is the verified default", func(t *testing.T) {
		if _, err := NewResolver().FetchPolicy(ctx, PolicyURL("example.com")); err == nil {
			t.Fatal("NewResolver().FetchPolicy with a cancelled context succeeded")
		}
	})

	t.Run("zero value caches", func(t *testing.T) {
		fetches := 0
		r := Resolver{
			LookupTXT: func(context.Context, string) ([]string, error) { return []string{"v=STSv1; id=abc"}, nil },
			FetchPolicy: func(context.Context, string) ([]byte, error) {
				fetches++
				return []byte("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"), nil
			},
		}
		for range 2 {
			if _, err := r.Resolve(context.Background(), "example.com"); err != nil {
				t.Fatal(err)
			}
		}
		if fetches != 1 {
			t.Fatalf("fetches = %d, want 1", fetches)
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

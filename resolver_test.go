package mtasts

import (
	"context"
	"errors"
	"fmt"
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

func TestParseTXTID(t *testing.T) {
	cases := []struct {
		name    string
		records []string
		wantID  string
		wantOK  bool
	}{
		{"single valid", []string{"v=STSv1; id=20230101Z"}, "20230101Z", true},
		{"spacing", []string{" v = STSv1 ; id = xyz "}, "xyz", true},
		{"ignores non-sts records", []string{"v=spf1 -all", "v=STSv1; id=aaa"}, "aaa", true},
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

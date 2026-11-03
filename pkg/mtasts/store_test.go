package mtasts

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// jsonStore is a PolicyStore that keeps each entry as JSON, as a file or
// database a host writes would, so nothing in memory is shared between the
// Resolver that saves an entry and the one that loads it.
type jsonStore struct {
	mu      sync.Mutex
	entries map[string][]byte
	loadErr error
	saveErr error
	deletes []string
}

func newJSONStore() *jsonStore { return &jsonStore{entries: map[string][]byte{}} }

func (s *jsonStore) Load(_ context.Context, domain string) (*StoredPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	b, ok := s.entries[domain]
	if !ok {
		return nil, nil
	}
	var sp StoredPolicy
	if err := json.Unmarshal(b, &sp); err != nil {
		return nil, err
	}
	return &sp, nil
}

func (s *jsonStore) Save(_ context.Context, domain string, sp StoredPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	b, err := json.Marshal(sp)
	if err != nil {
		return err
	}
	s.entries[domain] = b
	return nil
}

func (s *jsonStore) Delete(_ context.Context, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes = append(s.deletes, domain)
	delete(s.entries, domain)
	return nil
}

func (s *jsonStore) has(domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entries[domain]
	return ok
}

const storeTestPolicy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.mx.example.com\nmax_age: 3600\n"

// restarted returns a new Resolver, as after a restart, sharing only the
// store and the clock with f.
func restarted(f *fakeResolver, store PolicyStore) *fakeResolver {
	g := newFakeResolver()
	g.now = f.now
	g.Store = store
	return g
}

// TestResolvePolicySurvivesRestart checks that a policy saved by one Resolver
// is applied by a new one, as after a restart, while discovery is blocked
// (the RFC 8461 §10.2 downgrade), and that it still expires when its max_age
// runs out from the original fetch.
//
// checklist: MTASTS-CACHE-01 MTASTS-CACHE-03 MTASTS-APPLY-06
func TestResolvePolicySurvivesRestart(t *testing.T) {
	ctx := context.Background()
	store := newJSONStore()
	f := newFakeResolver()
	f.Store = store
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=abc"}
	f.policies[PolicyURL("example.com")] = storeTestPolicy
	want, err := f.Resolve(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !store.has("example.com") {
		t.Fatal("the fetched policy was not saved")
	}

	// After a restart, an attacker blocks the TXT lookup and the fetch.
	g := restarted(f, store)
	g.now = f.now.Add(3599 * time.Second)
	g.txtErr = errors.New("SERVFAIL")
	g.fetchErr = errors.New("connection reset")
	var refreshFailed int
	g.RefreshFailed = func(context.Context, string, *Policy, error) { refreshFailed++ }
	got, err := g.Resolve(ctx, "example.com")
	if err != nil {
		t.Fatalf("Resolve after restart: %v", err)
	}
	if got.Mode != want.Mode || got.MaxAge != want.MaxAge || len(got.MX) != 2 || got.MX[0] != want.MX[0] || got.MX[1] != want.MX[1] {
		t.Errorf("restored policy = %+v, want %+v", got, want)
	}
	if refreshFailed != 1 || g.fetchCount != 0 {
		t.Errorf("RefreshFailed called %d times and %d fetches, want 1 and 0", refreshFailed, g.fetchCount)
	}

	// Another restart once max_age has run out from the first fetch: the
	// stored policy is not applied, and is deleted.
	h := restarted(f, store)
	h.now = f.now.Add(3600 * time.Second)
	h.txtErr = errors.New("SERVFAIL")
	if p, err := h.Resolve(ctx, "example.com"); !errors.Is(err, ErrNoPolicy) {
		t.Errorf("Resolve after max_age = (%+v, %v), want ErrNoPolicy", p, err)
	}
	if store.has("example.com") {
		t.Error("the expired policy is still stored")
	}
}

// TestResolveRestoredPolicyKeepsItsFetchTime checks that a restored policy is
// served without a fetch while its id is unchanged, and that its daily
// refresh still runs a day after the original fetch, not after the restart.
//
// checklist: MTASTS-CACHE-01
func TestResolveRestoredPolicyKeepsItsFetchTime(t *testing.T) {
	ctx := context.Background()
	store := newJSONStore()
	f := newFakeResolver()
	f.Store = store
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=abc"}
	f.policies[PolicyURL("example.com")] = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n"
	if _, err := f.Resolve(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}

	g := restarted(f, store)
	g.txt = f.txt
	g.policies = f.policies
	g.now = f.now.Add(23 * time.Hour)
	if _, err := g.Resolve(ctx, "example.com"); err != nil || g.fetchCount != 0 {
		t.Fatalf("Resolve = %v with %d fetches, want the restored policy and no fetch", err, g.fetchCount)
	}
	g.now = f.now.Add(24 * time.Hour)
	if _, err := g.Resolve(ctx, "example.com"); err != nil || g.fetchCount != 1 {
		t.Fatalf("Resolve = %v with %d fetches, want the daily refresh", err, g.fetchCount)
	}
}

// TestResolveStoredPolicyBoundedByMaxAge checks that a stored expiry later
// than the policy's own max_age allows is cut to it, and that an invalid
// stored policy is never applied.
//
// checklist: MTASTS-APPLY-06
func TestResolveStoredPolicyBoundedByMaxAge(t *testing.T) {
	ctx := context.Background()
	base := time.Unix(1_700_000_000, 0)
	valid := Policy{Version: Version, Mode: ModeEnforce, MX: []string{"mail.example.com"}, MaxAge: 60}
	cases := []struct {
		name    string
		policy  Policy
		after   time.Duration
		applied bool
		invalid bool
	}{
		{"within max_age", valid, 59 * time.Second, true, false},
		{"past max_age, before the stored expiry", valid, 60 * time.Second, false, false},
		{"bad mode", Policy{Version: Version, Mode: "always", MX: valid.MX, MaxAge: 60}, time.Second, false, true},
		{"bad version", Policy{Version: "STSv2", Mode: ModeEnforce, MX: valid.MX, MaxAge: 60}, time.Second, false, true},
		{"enforce without mx", Policy{Version: Version, Mode: ModeEnforce, MaxAge: 60}, time.Second, false, true},
		{"bad mx", Policy{Version: Version, Mode: ModeEnforce, MX: []string{"mail/x"}, MaxAge: 60}, time.Second, false, true},
		{"max_age too large", Policy{Version: Version, Mode: ModeEnforce, MX: valid.MX, MaxAge: 31557601}, time.Second, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := newJSONStore()
			_ = store.Save(ctx, "example.com", StoredPolicy{ID: "abc", Policy: c.policy, FetchedAt: base, ExpiresAt: base.Add(time.Hour)})
			f := newFakeResolver()
			f.Store = store
			f.now = base.Add(c.after)
			f.txtErr = errors.New("SERVFAIL")
			var failures []error
			f.StoreFailed = func(_ context.Context, _ string, err error) { failures = append(failures, err) }
			p, err := f.Resolve(ctx, "example.com")
			if c.applied != (err == nil) {
				t.Fatalf("Resolve = (%+v, %v), applied = %v", p, err, c.applied)
			}
			if c.invalid != (len(failures) == 1 && errors.Is(failures[0], ErrStoredPolicyInvalid)) {
				t.Errorf("StoreFailed got %v", failures)
			}
			if !c.applied && store.has("example.com") {
				t.Error("a stored policy that cannot be applied was kept")
			}
		})
	}
}

// TestResolveStoreFailures checks that a failing store is reported and costs
// only the cache: Resolve still discovers the policy.
//
// checklist: MTASTS-CACHE-01
func TestResolveStoreFailures(t *testing.T) {
	ctx := context.Background()
	store := newJSONStore()
	store.loadErr = errors.New("disk on fire")
	store.saveErr = errors.New("disk full")
	f := newFakeResolver()
	f.Store = store
	var failures []error
	f.StoreFailed = func(_ context.Context, _ string, err error) { failures = append(failures, err) }
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=abc"}
	f.policies[PolicyURL("example.com")] = storeTestPolicy
	if _, err := f.Resolve(ctx, "example.com"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(failures) != 2 || !errors.Is(failures[0], store.loadErr) || !errors.Is(failures[1], store.saveErr) {
		t.Errorf("StoreFailed got %v, want the load and the save error", failures)
	}
	// The policy is still cached in memory, and memory is not reloaded.
	if _, err := f.Resolve(ctx, "example.com"); err != nil || f.fetchCount != 1 || len(failures) != 2 {
		t.Errorf("second Resolve = %v, %d fetches, %d failures", err, f.fetchCount, len(failures))
	}
}

// TestResolveMaxAgeZeroDeletesStoredPolicy checks that a policy with max_age
// 0, which is applied but not cached, also replaces the stored one.
//
// checklist: MTASTS-CACHE-01
func TestResolveMaxAgeZeroDeletesStoredPolicy(t *testing.T) {
	ctx := context.Background()
	store := newJSONStore()
	f := newFakeResolver()
	f.Store = store
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=abc"}
	f.policies[PolicyURL("example.com")] = storeTestPolicy
	if _, err := f.Resolve(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=def"}
	f.policies[PolicyURL("example.com")] = "version: STSv1\nmode: none\nmax_age: 0\n"
	if p, err := f.Resolve(ctx, "example.com"); err != nil || p.Mode != ModeNone {
		t.Fatalf("Resolve = (%+v, %v)", p, err)
	}
	if store.has("example.com") {
		t.Error("the replaced policy is still stored")
	}
}

// TestResolveULabelDomain checks that a recipient domain given in U-labels
// is looked up, fetched and cached by its A-labels, so it gets the policy its
// A-label form publishes.
//
// checklist: MTASTS-TXT-01 MTASTS-POL-01 MTASTS-DOM-03
func TestResolveULabelDomain(t *testing.T) {
	ctx := context.Background()
	f := newFakeResolver()
	var names []string
	lookup := f.LookupTXT
	f.LookupTXT = func(ctx context.Context, name string) ([]string, error) {
		names = append(names, name)
		return lookup(ctx, name)
	}
	f.txt["_mta-sts.xn--bcher-kva.example"] = []string{"v=STSv1; id=abc"}
	f.policies["https://mta-sts.xn--bcher-kva.example/.well-known/mta-sts.txt"] = "version: STSv1\nmode: enforce\nmx: mx.xn--bcher-kva.example\nmax_age: 86400\n"

	u, err := f.Resolve(ctx, "bücher.example")
	if err != nil {
		t.Fatalf("Resolve(U-label): %v", err)
	}
	if u.Mode != ModeEnforce {
		t.Errorf("Resolve(U-label) = %+v", u)
	}
	for _, domain := range []string{"xn--bcher-kva.example", "BÜCHER.example."} {
		p, err := f.Resolve(ctx, domain)
		if err != nil || p != u {
			t.Errorf("Resolve(%q) = (%+v, %v), want the policy cached for bücher.example", domain, p, err)
		}
	}
	if f.fetchCount != 1 {
		t.Errorf("%d fetches, want 1: both forms share one cache entry", f.fetchCount)
	}
	for _, name := range names {
		if name != "_mta-sts.xn--bcher-kva.example" {
			t.Errorf("looked up %q", name)
		}
	}
	if got, want := TXTName("Bücher.example"), "_mta-sts.xn--bcher-kva.example"; got != want {
		t.Errorf("TXTName = %q, want %q", got, want)
	}
	if got, want := PolicyURL("bücher.example."), "https://mta-sts.xn--bcher-kva.example/.well-known/mta-sts.txt"; got != want {
		t.Errorf("PolicyURL = %q, want %q", got, want)
	}
	// A name with no A-label form is left as given, and resolves nowhere.
	if got, want := TXTName("Bü/cher.example"), "_mta-sts.bü/cher.example"; got != want {
		t.Errorf("TXTName = %q, want %q", got, want)
	}
}

package policycache

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestStoreOversizedMaxAgeCachesInsteadOfExpiring is the resolver-side guard for
// issue #7. A policy whose max_age overflows time.Duration when multiplied by a
// second (> 9223372036) must still yield a future expiry — clamped to the cache
// cap — rather than a negative TTL that makes the entry expire immediately and
// forces a re-fetch on every outbound message (defeating the cache-based
// downgrade protection of RFC 8461 §10.2).
//
// checklist: MTASTS-CACHE-01
func TestStoreOversizedMaxAgeCachesInsteadOfExpiring(t *testing.T) {
	var c Cache[struct{}]
	now := time.Unix(1_700_000_000, 0)
	// 9223372037 * 1e9 ns overflows int64, wrapping to a negative Duration on
	// unfixed code.
	policy := &struct{}{}
	c.Store("example.com", "id1", policy, 9223372037, now)

	if got := c.Cached("example.com", "id1", now); got == nil {
		t.Fatal("oversized max_age produced an already-expired entry (negative TTL); want cached policy")
	}
	// A negative max_age, possible only in a Policy built by hand, caches
	// nothing.
	c.Store("neg.example", "id1", policy, -1, now)
	if got := c.Fallback("neg.example", now); got != nil {
		t.Error("a negative max_age was cached")
	}
	// The clamped entry must still be valid just shy of the cache cap.
	if got := c.Fallback("example.com", now.Add(maxCacheTTL-time.Second)); got == nil {
		t.Fatal("entry expired before the cache cap; TTL was not clamped to maxCacheTTL")
	}
}

// TestExpiredEntriesAreRemoved checks that a lookup removes the entry it finds
// expired, and that a store sweeps out every expired entry, at most once per
// sweepInterval, while entries still in force stay (issue #39).
//
// checklist: MTASTS-CACHE-01 MTASTS-FETCH-08
func TestExpiredEntriesAreRemoved(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	policy := &struct{}{}
	failure := errors.New("down")

	t.Run("a lookup removes what it finds expired", func(t *testing.T) {
		var c Cache[struct{}]
		c.Store("a.example", "1", policy, 60, now)
		c.Store("b.example", "1", policy, 60, now)
		c.StoreFailure("c.example", "1", now, failure, 0)
		later := now.Add(defaultNegativeTTL)
		if c.Cached("a.example", "1", later) != nil || c.Fallback("b.example", later) != nil {
			t.Fatal("an expired policy was served")
		}
		if _, ok := c.RecentlyFailed("c.example", "1", later); ok {
			t.Fatal("an expired failure suppressed a retry")
		}
		if p, f := c.Len(); p != 0 || f != 0 {
			t.Errorf("Len = %d policies, %d failures; want both removed", p, f)
		}
	})

	t.Run("a live failure for another id stays", func(t *testing.T) {
		var c Cache[struct{}]
		c.StoreFailure("a.example", "1", now, failure, 0)
		if _, ok := c.RecentlyFailed("a.example", "2", now); ok {
			t.Fatal("a failure for id 1 suppressed id 2")
		}
		if err, ok := c.RecentlyFailed("a.example", "1", now); !ok || err != failure {
			t.Fatalf("RecentlyFailed = (%v, %v), want the live failure", err, ok)
		}
	})

	t.Run("a store sweeps domains never looked up again", func(t *testing.T) {
		var c Cache[struct{}]
		for i := range 100 {
			c.Store(fmt.Sprintf("p%d.example", i), "1", policy, 60, now)
			c.StoreFailure(fmt.Sprintf("f%d.example", i), "1", now, failure, 0)
		}
		c.Store("long.example", "1", policy, 86400, now)
		c.StoreFailure("longfail.example", "1", now, failure, time.Hour)

		// Within sweepInterval of the last sweep, a store does not sweep.
		c.Store("new1.example", "1", policy, 60, now.Add(sweepInterval-time.Second))
		if p, f := c.Len(); p != 102 || f != 101 {
			t.Fatalf("Len before the interval = (%d, %d), want (102, 101)", p, f)
		}

		later := now.Add(sweepInterval)
		c.Store("new2.example", "1", policy, 60, later)
		if p, f := c.Len(); p != 3 || f != 1 {
			t.Fatalf("Len after the sweep = (%d, %d), want (3, 1): long, new1, new2 and longfail", p, f)
		}
		if c.Fallback("long.example", later) == nil {
			t.Error("the sweep dropped a policy still in force")
		}
		if _, ok := c.RecentlyFailed("longfail.example", "1", later); !ok {
			t.Error("the sweep dropped a failure still in force")
		}

		// A failure store sweeps too; a clock that went back does not.
		c.StoreFailure("x.example", "1", later.Add(-time.Hour), failure, 0)
		if p, _ := c.Len(); p != 3 {
			t.Fatalf("a store with the clock moved back swept: %d policies", p)
		}
		c.StoreFailure("y.example", "1", later.Add(2*sweepInterval), failure, 0)
		if p, f := c.Len(); p != 1 || f != 2 {
			t.Errorf("Len after the failure store's sweep = (%d, %d), want (1, 2): long; longfail and y", p, f)
		}
	})

	t.Run("max_age 0 replaces a cached policy and keeps nothing", func(t *testing.T) {
		var c Cache[struct{}]
		c.Store("a.example", "1", policy, 60, now)
		c.Store("a.example", "2", policy, 0, now)
		if p, _ := c.Len(); p != 0 {
			t.Errorf("Len = %d policies, want 0", p)
		}
	})
}

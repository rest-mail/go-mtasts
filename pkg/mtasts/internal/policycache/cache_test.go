package policycache

import (
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

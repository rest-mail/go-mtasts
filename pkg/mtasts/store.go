package mtasts

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/rest-mail/go-mtasts/pkg/mtasts/internal/domainname"
	"github.com/rest-mail/go-mtasts/pkg/mtasts/internal/policygrammar"
)

// PolicyStore keeps a Resolver's cached policies where they outlive the
// process, so a restart does not empty the cache. RFC 8461 §5.1 expects a
// sender to keep a policy for its max_age, and a policy it holds is what
// defeats the §10.2 downgrade attack: an attacker who blocks the TXT lookup or
// the policy fetch cannot strip it. Without a store, the cache is empty after
// every restart until each policy is fetched again.
//
// The library chooses no backend: a file, a database table or a key-value
// store all fit. Each method may be called from several goroutines at once.
type PolicyStore interface {
	// Load returns the policy stored for domain, or nil and a nil error when
	// none is. Resolve calls it when its in-memory cache holds no policy for
	// domain, so it runs once per Resolve call for a domain without one; keep
	// it fast.
	Load(ctx context.Context, domain string) (*StoredPolicy, error)
	// Save stores a newly fetched policy for domain, replacing any earlier one.
	Save(ctx context.Context, domain string, p StoredPolicy) error
	// Delete removes domain's stored policy: it has expired, or a policy with
	// max_age 0 replaced it. Deleting a domain with none stored is no error.
	Delete(ctx context.Context, domain string) error
}

// StoredPolicy is one domain's cached policy as a PolicyStore keeps it.
type StoredPolicy struct {
	// ID is the policy id from the _mta-sts TXT record the policy was fetched
	// under (RFC 8461 §3.1).
	ID string
	// Policy is the policy itself.
	Policy Policy
	// FetchedAt is when the policy fetch completed; its max_age, and its daily
	// refresh, run from then.
	FetchedAt time.Time
	// ExpiresAt is when the policy's max_age runs out. A loaded policy is
	// applied only before then, and never after FetchedAt plus its MaxAge.
	ExpiresAt time.Time
}

// ErrStoredPolicyInvalid is reported to Resolver.StoreFailed when a
// PolicyStore returns a policy that is not a valid MTA-STS policy; it is
// ignored, and deleted from the store.
var ErrStoredPolicyInvalid = errors.New("mtasts: the stored policy is not valid")

// restore loads domain's stored policy into the in-memory cache when the
// cache holds none. An expired or invalid stored policy is deleted.
func (r *Resolver) restore(ctx context.Context, domain string) {
	if r.Store == nil || r.cache.Has(domain, r.now()) {
		return
	}
	sp, err := r.Store.Load(ctx, domain)
	if err != nil {
		r.storeFailed(ctx, domain, err)
		return
	}
	if sp == nil {
		return
	}
	if !validStoredPolicy(&sp.Policy) {
		r.storeFailed(ctx, domain, ErrStoredPolicyInvalid)
		r.deleteStored(ctx, domain)
		return
	}
	// The policy's own max_age bounds the expiry, whatever the store says.
	expiresAt := sp.ExpiresAt
	if limit := sp.FetchedAt.Add(time.Duration(sp.Policy.MaxAge) * time.Second); expiresAt.After(limit) {
		expiresAt = limit
	}
	now := r.now()
	if !now.Before(expiresAt) {
		r.deleteStored(ctx, domain)
		return
	}
	p := sp.Policy
	p.MX = slices.Clone(p.MX)
	r.cache.Restore(domain, sp.ID, &p, sp.FetchedAt, expiresAt, now)
}

// save writes a newly fetched policy through to the store, or deletes the
// stored one when the policy was not cached (max_age 0).
func (r *Resolver) save(ctx context.Context, domain, id string, p *Policy, fetchedAt, expiresAt time.Time) {
	if r.Store == nil {
		return
	}
	if expiresAt.IsZero() {
		r.deleteStored(ctx, domain)
		return
	}
	sp := StoredPolicy{ID: id, Policy: *p, FetchedAt: fetchedAt, ExpiresAt: expiresAt}
	sp.Policy.MX = slices.Clone(p.MX)
	if err := r.Store.Save(ctx, domain, sp); err != nil {
		r.storeFailed(ctx, domain, err)
	}
}

func (r *Resolver) deleteStored(ctx context.Context, domain string) {
	if err := r.Store.Delete(ctx, domain); err != nil {
		r.storeFailed(ctx, domain, err)
	}
}

func (r *Resolver) storeFailed(ctx context.Context, domain string, err error) {
	if r.StoreFailed != nil {
		r.StoreFailed(ctx, domain, err)
	}
}

// validStoredPolicy reports whether p holds what ParsePolicy would accept, so
// a damaged or tampered store cannot make Resolve apply a policy no domain
// could publish (RFC 8461 §5: apply only a valid policy).
func validStoredPolicy(p *Policy) bool {
	if p.Version != Version || p.MaxAge < 0 || p.MaxAge > policygrammar.MaxAgeLimit {
		return false
	}
	switch p.Mode {
	case ModeEnforce, ModeTesting:
		if len(p.MX) == 0 {
			return false
		}
	case ModeNone:
	default:
		return false
	}
	for _, mx := range p.MX {
		if !domainname.ValidMXPattern(mx) {
			return false
		}
	}
	return true
}

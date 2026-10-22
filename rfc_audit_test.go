package mtasts

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A CNAME delegates the TXT contents, not the HTTPS origin or its identity.
// Both certificate cases use the same trusted CA and reachable endpoint.
//
// checklist: MTASTS-DELEGATE-01
func TestDelegatedPolicyKeepsOriginalIdentity(t *testing.T) {
	ca := newTestCA(t)
	for _, host := range []string{"mta-sts.example.com", "mta-sts.provider.example"} {
		t.Run(host, func(t *testing.T) {
			requests := make(chan string, 1)
			fetcher, _ := policyHost(t, ca, ca.leaf(t, []string{host}, nil), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests <- req.Host + " " + req.URL.Path + " " + req.TLS.ServerName
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(testPolicyBody))
			}), nil)
			dns := &net.Resolver{PreferGo: true, Dial: fakeDNS(t, []string{"_mta-sts.provider.example"}, []string{"v=STSv1; id=delegated"})}
			r := NewResolver()
			r.LookupTXT = dns.LookupTXT
			r.FetchPolicy = fetcher.Fetch
			p, err := r.Resolve(context.Background(), "example.com")
			if host == "mta-sts.example.com" {
				if err != nil || p == nil || p.Mode != ModeEnforce {
					t.Fatalf("delegated policy: (%+v, %v)", p, err)
				}
				select {
				case got := <-requests:
					if want := "mta-sts.example.com /.well-known/mta-sts.txt mta-sts.example.com"; got != want {
						t.Fatalf("Host, path, SNI = %q, want %q", got, want)
					}
				default:
					t.Fatal("no HTTPS request")
				}
			} else {
				if p != nil || !errors.Is(err, ErrNoPolicy) {
					t.Fatalf("provider-only certificate accepted: (%+v, %v)", p, err)
				}
				if len(requests) != 0 {
					t.Fatal("HTTP request sent despite wrong certificate identity")
				}
			}
		})
	}
}

// Authenticated none replaces enforce before the latter's original expiry.
// Removing DNS/HTTPS alone cannot opt out; none remains cached without alerts
// until its own max_age expires, then discovery fails open.
//
// checklist: MTASTS-REMOVE-01
func TestResolveAuthenticatedRemoval(t *testing.T) {
	f := newFakeResolver()
	ctx := context.Background()
	name, url := TXTName("example.com"), PolicyURL("example.com")
	f.txt[name] = []string{"v=STSv1; id=enforcing"}
	f.policies[url] = testPolicyBody
	p, err := f.Resolve(ctx, "example.com")
	if err != nil || p.Mode != ModeEnforce {
		t.Fatalf("initial policy: (%+v, %v)", p, err)
	}
	delete(f.txt, name)
	delete(f.policies, url)
	if got, err := f.Resolve(ctx, "example.com"); err != nil || got != p {
		t.Fatalf("endpoint deletion removed enforce: (%+v, %v)", got, err)
	}
	f.policies[url] = "version: STSv1\nmode: none\nmax_age: 60\n"
	f.txt[name] = []string{"v=STSv1; id=removed"}
	p, err = f.Resolve(ctx, "example.com")
	if err != nil || p.Mode != ModeNone || f.fetchCount != 2 {
		t.Fatalf("none replacement: (%+v, %v), fetches %d", p, err, f.fetchCount)
	}
	if err := Evaluate(EvalInput{Policy: p, MXHost: "unlisted.example"}); err != nil {
		t.Fatalf("none blocked delivery: %v", err)
	}
	alerts := 0
	f.RefreshFailed = func(string, *Policy, error) { alerts++ }
	delete(f.txt, name)
	delete(f.policies, url)
	f.now = f.now.Add(59 * time.Second)
	if got, err := f.Resolve(ctx, "example.com"); err != nil || got != p || alerts != 0 {
		t.Fatalf("cached none: (%+v, %v), alerts %d", got, err, alerts)
	}
	f.now = f.now.Add(time.Second)
	if got, err := f.Resolve(ctx, "example.com"); got != nil || !errors.Is(err, ErrNoPolicy) || alerts != 0 {
		t.Fatalf("expired none: (%+v, %v), alerts %d", got, err, alerts)
	}
}

// Cache validity must be judged after blocking I/O, including at exact expiry.
//
// checklist: MTASTS-APPLY-06 MTASTS-FETCH-10 MTASTS-FETCH-11
func TestResolveExpiryDuringDiscovery(t *testing.T) {
	for _, failure := range []string{"DNS error", "missing TXT", "fetch error", "invalid policy", "negative cache"} {
		for _, delay := range []time.Duration{0, time.Second, 2 * time.Second} {
			t.Run(failure+"/"+delay.String(), func(t *testing.T) {
				f := newFakeResolver()
				ctx := context.Background()
				name, url := TXTName("example.com"), PolicyURL("example.com")
				f.txt[name] = []string{"v=STSv1; id=old"}
				f.policies[url] = strings.Replace(testPolicyBody, "86400", "100", 1)
				old, err := f.Resolve(ctx, "example.com")
				if err != nil {
					t.Fatal(err)
				}
				f.now = f.now.Add(99 * time.Second)
				f.txt[name] = []string{"v=STSv1; id=new"}
				if failure == "negative cache" {
					f.fetchErr = errors.New("failed before expiry")
					if _, err := f.Resolve(ctx, "example.com"); err != nil {
						t.Fatal(err)
					}
				}
				lookup := f.LookupTXT
				f.LookupTXT = func(ctx context.Context, name string) ([]string, error) {
					switch failure {
					case "DNS error":
						f.now = f.now.Add(delay)
						return nil, errors.New("slow DNS failure")
					case "missing TXT":
						f.now = f.now.Add(delay)
						return nil, nil
					case "negative cache":
						f.now = f.now.Add(delay)
					}
					return lookup(ctx, name)
				}
				f.FetchPolicy = func(context.Context, string) ([]byte, error) {
					f.now = f.now.Add(delay)
					if failure == "invalid policy" {
						return []byte("not a policy"), nil
					}
					if failure == "negative cache" {
						t.Fatal("negative-cached failure retried")
					}
					return nil, errors.New("slow fetch failure")
				}
				got, err := f.Resolve(ctx, "example.com")
				if delay == 0 {
					if err != nil || got != old {
						t.Fatalf("unexpired policy lost: (%+v, %v)", got, err)
					}
				} else if got != nil || !errors.Is(err, ErrNoPolicy) {
					t.Fatalf("expired policy returned: (%+v, %v)", got, err)
				}
			})
		}
	}
}

// An unchanged TXT id cannot keep an expired policy on the fast path when
// the DNS lookup itself consumed the last second of its lifetime.
//
// checklist: MTASTS-APPLY-06 MTASTS-CACHE-02
func TestResolveExpiryDuringSuccessfulLookup(t *testing.T) {
	f := newFakeResolver()
	f.txt[TXTName("example.com")] = []string{"v=STSv1; id=same"}
	f.policies[PolicyURL("example.com")] = strings.Replace(testPolicyBody, "86400", "100", 1)
	ctx := context.Background()
	if _, err := f.Resolve(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(99 * time.Second)
	lookup := f.LookupTXT
	f.LookupTXT = func(ctx context.Context, name string) ([]string, error) {
		f.now = f.now.Add(time.Second)
		return lookup(ctx, name)
	}
	f.policies[PolicyURL("example.com")] = "version: STSv1\nmode: none\nmax_age: 100\n"
	p, err := f.Resolve(ctx, "example.com")
	if err != nil || p.Mode != ModeNone || f.fetchCount != 2 {
		t.Fatalf("expired same-id policy not refreshed: (%+v, %v), fetches %d", p, err, f.fetchCount)
	}
}

// The positive and negative lifetimes start when an attempt finishes, rather
// than losing their lifetime to the DNS lookup or HTTPS download itself.
//
// checklist: MTASTS-CACHE-01 MTASTS-FETCH-08
func TestResolveLifetimesStartAfterFetch(t *testing.T) {
	for _, success := range []bool{true, false} {
		name := "failed fetch"
		if success {
			name = "successful fetch"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeResolver()
			f.txt[TXTName("example.com")] = []string{"v=STSv1; id=same"}
			calls := 0
			f.FetchPolicy = func(context.Context, string) ([]byte, error) {
				calls++
				f.now = f.now.Add(10 * time.Minute)
				if !success {
					return nil, errors.New("slow fetch failure")
				}
				return []byte(strings.Replace(testPolicyBody, "86400", "100", 1)), nil
			}
			ctx := context.Background()
			p, err := f.Resolve(ctx, "example.com")
			if success && (err != nil || p == nil) || !success && (p != nil || !errors.Is(err, ErrNoPolicy)) {
				t.Fatalf("initial fetch: (%+v, %v)", p, err)
			}
			ttl := defaultNegativeTTL
			if success {
				ttl = 100 * time.Second
			}
			f.now = f.now.Add(ttl - time.Nanosecond)
			_, _ = f.Resolve(ctx, "example.com")
			if calls != 1 {
				t.Fatalf("retried before lifetime elapsed: %d fetches", calls)
			}
			f.now = f.now.Add(time.Nanosecond)
			_, _ = f.Resolve(ctx, "example.com")
			if calls != 2 {
				t.Fatalf("not retried at lifetime boundary: %d fetches", calls)
			}
		})
	}
}

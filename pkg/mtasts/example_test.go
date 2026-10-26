package mtasts_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/rest-mail/go-mtasts/pkg/mtasts"
)

// Example discovers a domain's MTA-STS policy and then judges one delivery
// attempt against it. It injects in-memory DNS and HTTPS so the round trip is
// self-contained. In production, use mtasts.NewResolver() as-is: it reads real
// _mta-sts.<domain> TXT records and fetches the policy over verified HTTPS.
//
// checklist: MTASTS-CACHE-02 MTASTS-MX-01
func Example() {
	r := mtasts.NewResolver()

	// Serve the _mta-sts.example.com TXT record from memory. It carries the
	// policy id that tells the resolver whether its cache is still fresh.
	r.LookupTXT = func(_ context.Context, _ string) ([]string, error) {
		return []string{"v=STSv1; id=20260101T000000Z"}, nil
	}
	// Serve https://mta-sts.example.com/.well-known/mta-sts.txt from memory.
	r.FetchPolicy = func(_ context.Context, _ string) ([]byte, error) {
		return []byte("version: STSv1\n" +
			"mode: enforce\n" +
			"mx: mail.example.com\n" +
			"mx: *.mx.example.com\n" +
			"max_age: 604800\n"), nil
	}

	policy, err := r.Resolve(context.Background(), "example.com")
	if err != nil {
		// ErrNoPolicy (or any error) means fall back to opportunistic TLS.
		panic(err)
	}

	// After connecting to an MX host and negotiating STARTTLS, judge the
	// attempt. Evaluate returns nil when delivery may proceed and a deferrable
	// *EnforceError when an "enforce" policy is violated.
	err = mtasts.Evaluate(mtasts.EvalInput{
		Policy:    policy,
		Domain:    "example.com",
		MXHost:    "mail.example.com",
		STARTTLS:  true,
		CertValid: true,
	})

	fmt.Printf("mode=%s mx-covered=%v deliver-err=%v\n",
		policy.Mode, policy.MatchesMX("mail.example.com"), err)
	// Output: mode=enforce mx-covered=true deliver-err=<nil>
}

// ExampleParsePolicy parses a policy file body directly (without discovery) and
// checks whether a given MX host is covered by it.
//
// checklist: MTASTS-MX-03
func ExampleParsePolicy() {
	body := []byte("version: STSv1\n" +
		"mode: enforce\n" +
		"mx: mail.example.com\n" +
		"mx: *.mx.example.com\n" +
		"max_age: 604800\n")

	policy, err := mtasts.ParsePolicy(body)
	if err != nil {
		panic(err)
	}

	fmt.Println(policy.MatchesMX("mail.example.com"))     // exact host
	fmt.Println(policy.MatchesMX("relay.mx.example.com")) // one wildcard label
	fmt.Println(policy.MatchesMX("mx.example.com"))       // wildcard needs a label
	// Output:
	// true
	// true
	// false
}

// ExampleEvaluate_traverse walks the MX candidates in preference order, as
// RFC 8461 section 8.4 asks: the list is not filtered by the policy first, and
// a candidate that fails validation is passed over as though it were
// unreachable. Evaluate judges one candidate at a time, and its EnforceError
// is temporary, so the walk moves on to the next host and the message is
// deferred, not bounced, if none passes.
//
// checklist: MTASTS-MX-07
func ExampleEvaluate_traverse() {
	policy, err := mtasts.ParsePolicy([]byte("version: STSv1\n" +
		"mode: enforce\n" +
		"mx: mail.example.com\n" +
		"mx: *.mx.example.com\n" +
		"max_age: 604800\n"))
	if err != nil {
		panic(err)
	}

	// What each connection attempt found, in MX preference order.
	candidates := []struct {
		host                string
		starttls, certValid bool
	}{
		{"mx.attacker.example", true, true}, // not named by the policy
		{"mail.example.com", false, false},  // STARTTLS stripped
		{"a.mx.example.com", true, false},   // certificate not valid
		{"b.mx.example.com", true, true},
		{"c.mx.example.com", true, true}, // not reached
	}
	for _, c := range candidates {
		err := mtasts.Evaluate(mtasts.EvalInput{
			Policy:    policy,
			Domain:    "example.com",
			MXHost:    c.host,
			STARTTLS:  c.starttls,
			CertValid: c.certValid,
		})
		var enforce *mtasts.EnforceError
		if errors.As(err, &enforce) && enforce.Temporary() {
			fmt.Printf("unreachable %s: %s\n", c.host, enforce.Reason)
			continue
		}
		fmt.Printf("deliver to %s (err=%v)\n", c.host, err)
		break
	}
	// Output:
	// unreachable mx.attacker.example: MX host not named by policy
	// unreachable mail.example.com: STARTTLS required but not established
	// unreachable a.mx.example.com: certificate not valid for MX host
	// deliver to b.mx.example.com (err=<nil>)
}

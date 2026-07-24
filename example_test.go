package mtasts_test

import (
	"context"
	"fmt"

	"github.com/rest-mail/go-mtasts"
)

// Example discovers a domain's MTA-STS policy and then judges one delivery
// attempt against it. It injects in-memory DNS and HTTPS so the round trip is
// self-contained. In production, use mtasts.NewResolver() as-is: it reads real
// _mta-sts.<domain> TXT records and fetches the policy over verified HTTPS.
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
		Mode:      policy.Mode,
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

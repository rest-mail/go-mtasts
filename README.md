# mtasts

[![CI](https://github.com/rest-mail/mtasts/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/mtasts/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/mtasts.svg)](https://pkg.go.dev/github.com/rest-mail/mtasts)

MTA-STS ([RFC 8461](https://www.rfc-editor.org/rfc/rfc8461)) policy discovery,
caching, and enforcement for Go, with zero external dependencies (standard
library only).

A sending MTA discovers a recipient domain's policy by reading its
`_mta-sts.<domain>` TXT record (which carries a policy id) and then fetching the
policy file from `https://mta-sts.<domain>/.well-known/mta-sts.txt`. When the
policy mode is `enforce` the sender MUST negotiate STARTTLS to an MX host that is
both named by the policy and presents a certificate valid for that host;
otherwise delivery is deferred rather than sent in the clear. Discovery
fails **open** (RFC 8461 section 5): a missing/invalid record, a fetch error, or
an unparseable policy all fall back to ordinary opportunistic TLS.

The package exposes each step so a caller can wire it into an outbound queue:

- **`Resolver`** — discovers and caches policies. `Resolve(ctx, domain)` returns
  the parsed `*Policy` or `ErrNoPolicy`. The DNS and HTTPS-fetch steps are
  injectable (`LookupTXT`, `FetchPolicy`, `Now`) so it can be unit-tested
  without the network, or pointed at an insecure fetch for a dev deployment.
- **`ParsePolicy`** — parses a policy file body (RFC 8461 section 3.2).
- **`Policy.MatchesMX` / `Policy.MatchesCert`** — the RFC 6125 pattern matching
  (exact host or a single leading `*.` wildcard label).
- **`Evaluate`** — applies a policy to one delivery attempt's observed TLS
  outcome, returning a deferrable `*EnforceError` when an `enforce` policy is
  violated.

## Install

```sh
go get github.com/rest-mail/mtasts
```

## Usage

```go
package main

import (
	"context"
	"fmt"

	"github.com/rest-mail/mtasts"
)

func main() {
	r := mtasts.NewResolver()

	policy, err := r.Resolve(context.Background(), "example.com")
	if err != nil {
		// ErrNoPolicy (or any error) means fall back to opportunistic TLS.
		return
	}

	// After connecting to an MX host and negotiating STARTTLS, judge the
	// attempt against the policy.
	err = mtasts.Evaluate(mtasts.EvalInput{
		Policy:    policy,
		Mode:      policy.Mode,
		Domain:    "example.com",
		MXHost:    "mail.example.com",
		STARTTLS:  true,
		CertValid: true,
	})
	if err != nil {
		// *EnforceError — deferrable: retry later rather than bounce.
		fmt.Println("MTA-STS enforce failed:", err)
	}
}
```

## License

[MIT](LICENSE) © 2026 rest-mail

# go-mtasts

[![CI](https://github.com/rest-mail/go-mtasts/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-mtasts/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-mtasts.svg)](https://pkg.go.dev/github.com/rest-mail/go-mtasts)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-mtasts)](https://goreportcard.com/report/github.com/rest-mail/go-mtasts)

MTA-STS ([RFC 8461](https://www.rfc-editor.org/rfc/rfc8461)) policy discovery,
caching, and enforcement for Go — standard library only, no external
dependencies.

## About

MTA-STS (SMTP MTA Strict Transport Security) lets a recipient domain declare
that senders MUST reach its mail servers over authenticated TLS. A sending MTA
discovers the policy by reading the recipient's `_mta-sts.<domain>` TXT record
(which carries a short policy id) and then fetching the policy file from
`https://mta-sts.<domain>/.well-known/mta-sts.txt`. The policy names the MX hosts
allowed to receive mail and a mode — `enforce`, `testing`, or `none`.

When the mode is `enforce` the sender MUST negotiate STARTTLS to an MX host that
is both named by the policy and presents a certificate valid for that host;
otherwise delivery is deferred rather than sent in the clear. Discovery fails
**open** (RFC 8461 section 5): a missing or invalid record, a fetch error, or an
unparseable policy all fall back to ordinary opportunistic TLS, so a broken
policy never blocks mail.

## Features

- Policy **discovery** with in-memory caching keyed by the TXT-record policy id,
  honouring `max_age` (capped at RFC 8461's one-year maximum).
- **Fail-open** semantics per RFC 8461 section 5 — a bad record or fetch yields
  `ErrNoPolicy` so the caller reverts to opportunistic TLS.
- **Enforcement** helper (`Evaluate`) that turns one attempt's observed TLS
  outcome into a deferrable `*EnforceError` under `enforce`.
- RFC 6125 MX pattern matching (`Policy.MatchesMX`, `Policy.MatchesCert`) — exact
  host or a single leading `*.` wildcard label.
- Standalone policy parser (`ParsePolicy`): lenient about unknown keys, strict
  about the fields an enforcement decision needs.
- Injectable DNS lookup, HTTPS fetch, and clock (`LookupTXT`, `FetchPolicy`,
  `Now`) so the resolver runs hermetically in tests, or against an insecure
  fetch in a dev deployment.
- Redirect-refusing, TLS-1.2+ policy fetch (`HTTPFetch`), per RFC 8461 section
  3.3.
- Zero external dependencies.

## Install

```sh
go get github.com/rest-mail/go-mtasts
```

## Quickstart

Discover a domain's policy, then judge one delivery attempt against it. In
production you would use `mtasts.NewResolver()` as-is — it reads real TXT records
and fetches the policy over verified HTTPS. Here in-memory DNS and HTTPS keep the
example self-contained and offline.

```go
package main

import (
	"context"
	"fmt"

	"github.com/rest-mail/go-mtasts"
)

func main() {
	r := mtasts.NewResolver()

	// Inject in-memory DNS + HTTPS so this runs with no network. In production,
	// leave NewResolver()'s defaults in place.
	r.LookupTXT = func(_ context.Context, _ string) ([]string, error) {
		return []string{"v=STSv1; id=20260101T000000Z"}, nil
	}
	r.FetchPolicy = func(_ context.Context, _ string) ([]byte, error) {
		return []byte("version: STSv1\nmode: enforce\n" +
			"mx: mail.example.com\nmx: *.mx.example.com\nmax_age: 604800\n"), nil
	}

	policy, err := r.Resolve(context.Background(), "example.com")
	if err != nil {
		// ErrNoPolicy (or any error) means fall back to opportunistic TLS.
		return
	}

	// After connecting to an MX host and negotiating STARTTLS, judge the attempt.
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

## Discovery

A `Resolver` discovers and caches policies. `Resolve(ctx, domain)` reads the
`_mta-sts.<domain>` TXT record for the policy id, serves a cached policy while
its `max_age` has not elapsed and the id is unchanged, and otherwise fetches and
parses the HTTPS policy file. It returns the parsed `*Policy` or `ErrNoPolicy`.
`TXTName` and `PolicyURL` expose the DNS name and URL the resolver derives from a
domain. If you fetch policy files yourself, `ParsePolicy` parses a body in
isolation.

## Enforcement

`Evaluate` applies a policy to one delivery attempt's observed TLS outcome
(`EvalInput`), returning `nil` when delivery may proceed and a deferrable
`*EnforceError` when an `enforce` policy is violated — the outbound queue should
retry rather than bounce. Under `enforce`, three conditions must all hold: the MX
host is named by the policy, STARTTLS succeeded, and the certificate is valid for
the MX host. `testing`, `none`, and "no policy" never block delivery. A caller
may downgrade `enforce` to `testing` via `EvalInput.Mode` (e.g. when certificate
verification is globally disabled for a dev deployment).

`Policy.MatchesMX` and `Policy.MatchesCert` perform the RFC 6125 pattern match —
an exact host, or a single leading `*.` wildcard label that matches exactly one
DNS label.

## Testing without a network

A `Resolver`'s DNS and HTTPS steps are injectable through its `LookupTXT`,
`FetchPolicy`, and `Now` fields, so discovery can be driven from in-memory data
in tests (see the [package example](https://pkg.go.dev/github.com/rest-mail/go-mtasts#example-package))
or pointed at an insecure fetch for a development deployment.

## Documentation

Full API reference:
[pkg.go.dev/github.com/rest-mail/go-mtasts](https://pkg.go.dev/github.com/rest-mail/go-mtasts).

## License

[MIT](LICENSE) © 2026 rest-mail

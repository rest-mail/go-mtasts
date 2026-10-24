# go-mtasts

[![CI](https://github.com/rest-mail/go-mtasts/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-mtasts/actions/workflows/ci.yml)
[![Coverage gate: ≥95%](https://img.shields.io/badge/coverage%20gate-%E2%89%A595%25-brightgreen)](COVERAGE.md)
[![Checklist: 55/86 mapped](https://img.shields.io/badge/checklist-55%2F86%20mapped-blue)](CHECKLIST.md)
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
  `ErrNoPolicy` so the caller reverts to opportunistic TLS, with the reason in
  the chain (`ErrNoRecord`, `ErrPolicyFetch`, `ErrPolicyInvalid`) for a TLS-RPT
  report.
- **Enforcement** helper (`Evaluate`) that turns one attempt's observed TLS
  outcome into a deferrable `*EnforceError` under `enforce`.
- RFC 6125 MX pattern matching (`Policy.MatchesMX`, `Policy.MatchesCert`) — exact
  host or a single leading `*.` wildcard label.
- Standalone policy parser (`ParsePolicy`): lenient about unknown keys, strict
  about the fields an enforcement decision needs.
- Injectable DNS lookup, HTTPS fetch, and clock (`LookupTXT`, `FetchPolicy`,
  `Now`) so the resolver runs hermetically in tests, or against an insecure
  fetch in a dev deployment.
- Redirect-refusing, TLS-1.2+ policy fetch (`Fetcher`, `HTTPFetch`), per RFC
  8461 section 3.3, with an injectable dialer and root CAs.
- Daily refresh of cached policies, and a `RefreshFailed` hook to alert
  administrators when a refresh fails (RFC 8461 §3.3, §10.2).
- Every RFC 8461 requirement on a sender checked item by item in
  [CHECKLIST.md](CHECKLIST.md), with a 95% coverage gate and fuzzing in CI.
- Zero external dependencies (the tests use foxcpp/go-mtasts).

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
A cached policy is fetched again once a day even when its id is unchanged, so it
is refreshed long before a long `max_age` runs out; when discovery fails and a
cached policy stays in force, `RefreshFailed` (if set) is told, so the caller
can alert an administrator. A `max_age` of 0 applies the policy without caching
it. A fetch or parse failure for a given id is negative-cached for `NegativeTTL`
(default 5 minutes after the failed attempt finishes), so a broken or blocked
policy host is not re-probed on every outbound message (RFC 8461 §3.3); a newly published id is fetched immediately.
`TXTName` and `PolicyURL` expose the DNS name and URL the resolver derives from a
domain; a recipient domain that is not a DNS name (an address literal, say) has
no policy. If you fetch policy files yourself, `ParsePolicy` parses a body in
isolation, and `Fetcher` does the HTTPS GET with the checks RFC 8461 asks for.

## Enforcement

`Evaluate` applies a policy to one delivery attempt's observed TLS outcome
(`EvalInput`), returning `nil` when delivery may proceed and a deferrable
`*EnforceError` when an `enforce` policy is violated — the outbound queue should
retry rather than bounce. Under `enforce`, three conditions must all hold: the MX
host is named by the policy, STARTTLS succeeded, and the certificate is valid for
the MX host. The effective mode is the discovered `Policy.Mode` (RFC 8461 §5), so
enforcement can't be silently disabled by a caller that forgets to restate it —
`testing`, `none`, and "no policy" never block delivery. A dev/test deployment
that has globally disabled certificate verification can set
`EvalInput.AllowInsecureDowngrade` to turn a would-fail into report-only; its zero
value fails closed, so this downgrade is always a deliberate opt-in.

`Policy.MatchesMX` and `Policy.MatchesCert` perform the RFC 6125 pattern match —
an exact host, or a single leading `*.` wildcard label that matches exactly one
DNS label.

## Testing without a network

A `Resolver`'s DNS and HTTPS steps are injectable through its `LookupTXT`,
`FetchPolicy`, and `Now` fields, so discovery can be driven from in-memory data
in tests (see the [package example](https://pkg.go.dev/github.com/rest-mail/go-mtasts#example-package))
or pointed at an insecure fetch for a development deployment. A `Fetcher`'s
`DialContext` and `RootCAs` let a test serve a policy host from memory with a
certificate it made itself.

## Testing

```sh
go test -race ./...                 # all tests, no network
go run ./internal/checklist         # CHECKLIST.md and the tests agree
go test -run='^$' -fuzz='^FuzzParsePolicy$' -fuzztime=30s .
python3 -m unittest discover -s .github/tests   # what CI passes the shared proof
```

CI runs these through go-spf's reusable
[`rfc-verification.yml`](https://github.com/rest-mail/go-spf/blob/7d291c08d310b9c62afc287e75a534a39150fafb/.github/workflows/rfc-verification.yml),
pinned to that commit; the required `Build & Test` check passes only when it
and the workflow fixtures in [`.github/tests`](.github/tests) both succeed.
CI also fails below 95% statement coverage; the lines left uncovered on
purpose are listed, each with a reason, in [COVERAGE.md](COVERAGE.md). The
coverage badge states this enforced minimum; the measured percentage is in
each CI run's `RFC proof` log. The checklist badge counts requirements mapped
to tests over all requirements, including `n/a` rows in the total. CI validates
the mappings and rejects a stale badge count. The current inventory contains
55 mapped requirements and 31 explicit `n/a` rows, including publisher and
SMTP transport duties outside this library. The section audit and responsibility
boundaries are recorded in CHECKLIST.md. These badges describe the
checked-in contract; the CI badge shows whether verification passed.

The fuzz targets are `FuzzParsePolicy` (any policy body; an accepted policy is valid and
parses again as itself when written out), `FuzzParseTXTRecord` (any TXT
record; an accepted id is valid and came from a US-ASCII record led by
`v=STSv1`) and `FuzzMatchesMX` (any pattern and host; a match ignores case and
a trailing dot, and a wildcard covers exactly one label); CI runs each for 30
seconds. Their seeds are in the targets, and inputs that once failed are kept
there or in `testdata/fuzz`.

The RFC's own examples are tests: the policy of §3.2, the TXT record and
policy of Appendix A run through discovery, and the wildcard examples of §4.1.
The HTTPS fetch is tested against policy hosts served from memory with
certificates made per test (wrong name, untrusted, expired, common name only,
wildcards, TLS 1.1), and the default TXT lookup against an in-memory DNS
server (strings joined, CNAME chains followed). No test touches the network.
Differential tests check MX matching against
[foxcpp/go-mtasts](https://github.com/foxcpp/go-mtasts) (MIT), on fixed vectors
and under the fuzzer, listing each place where the two disagree on purpose and
why (its policy and TXT parsers are not exported, so only matching is
compared). foxcpp/go-mtasts and golang.org/x/net are test-only dependencies;
the library does not import them.

### The RFC checklist

[CHECKLIST.md](CHECKLIST.md) lists the RFC's requirements item by item, and a
small program, [`internal/checklist`](internal/checklist/main.go), checks it
against the tests in CI. It is the same program as
[go-spf](https://github.com/rest-mail/go-spf)'s,
[go-dkim](https://github.com/rest-mail/go-dkim)'s and
[go-dmarc](https://github.com/rest-mail/go-dmarc)'s; other `go-*` libraries can
copy both.

The checklist is a Markdown file holding one or more tables whose header is
exactly:

```markdown
| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| MTASTS-FETCH-06 | 3.3 | MUST NOT | Follow HTTP 3xx redirects. | `TestHTTPFetchDoesNotFollowRedirect` |
| MTASTS-DOM-01 | 3.4 | MUST | When sending through a smart host, treat the smart host's domain as the Policy Domain. | n/a: the caller chooses the Policy Domain. |
```

- **ID** is unique, upper case, and ends in a number: a prefix for the RFC, an
  area, and a sequence number (`MTASTS-FETCH-06`).
- **Section** is the RFC section (or sections) the requirement comes from.
- **Level** is the RFC 2119 keyword it carries (`MUST`, `MUST NOT`, `SHOULD`,
  `SHOULD NOT`, `RECOMMENDED`, `NOT RECOMMENDED`, `MAY`, ...), or `Normative`
  for normative text without a keyword.
- **Requirement** says what is required, in one line (no `|`).
- **Tests** lists the test functions that cover it, separated by commas, or
  says `n/a:` and why it does not apply.

Each test names the items it covers in its doc comment:

```go
// TestFetcherSendsSNI checks that the TLS handshake names the policy host.
//
// checklist: MTASTS-FETCH-14
func TestFetcherSendsSNI(t *testing.T) {
```

`go run ./internal/checklist [-file CHECKLIST.md] [package dir ...]` scans the
`_test.go` files of the given package directories (default `.`) and fails when:

- an ID is used twice, or a row is malformed;
- an item names no test and is not marked `n/a`;
- an item lists a test that does not exist, or that does not name the item;
- a test names an item that does not exist, is `n/a`, or does not list it;
- a `Test` or `Fuzz` function names no item (`Example` functions may).

## Documentation

Full API reference:
[pkg.go.dev/github.com/rest-mail/go-mtasts](https://pkg.go.dev/github.com/rest-mail/go-mtasts).

## Changelog

Recent releases — see [CHANGELOG.md](CHANGELOG.md) for the complete history.

- **Unreleased** — checked against RFC 8461 item by item: cached policies refresh daily, with a `RefreshFailed` hook; `max_age: 0` is valid; mx patterns and TXT extension fields are validated; repeated TXT fields are ignored after the first; certificate matching ignores the subject CN; adds `Fetcher` and `EnforceError.Temporary`; an RFC checklist, a 95% coverage gate and fuzzing.
- **v0.2.1** (2026-07-25) — adds `Resolver.NegativeTTL` (negative caching of failed fetches); strict `_mta-sts` TXT parse, label-based wildcard MX, Content-Type validation.
- **v0.2.0** (2026-07-25) — security and correctness release; `Evaluate` derives the mode from the discovered `Policy.Mode` so enforcement fails closed (breaking: `EvalInput.Mode` removed, new `AllowInsecureDowngrade`); HTTPS-only policy fetch.
- **v0.1.1** (2026-07-23) — module renamed to `github.com/rest-mail/go-mtasts`; github-guard git hooks installed.
- **v0.1.0** (2026-07-23) — initial release: MTA-STS (RFC 8461) policy discovery, caching, and enforcement.

## License

[MIT](LICENSE) © 2026 rest-mail

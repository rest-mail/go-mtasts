# go-mtasts

[![CI](https://github.com/rest-mail/go-mtasts/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-mtasts/actions/workflows/ci.yml)
[![Coverage gate: ≥95%](https://img.shields.io/badge/coverage%20gate-%E2%89%A595%25-brightgreen)](COVERAGE.md)
[![Checklist: 55/86 mapped](https://img.shields.io/badge/checklist-55%2F86%20mapped-blue)](CHECKLIST.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-mtasts.svg)](https://pkg.go.dev/github.com/rest-mail/go-mtasts/pkg/mtasts)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-mtasts)](https://goreportcard.com/report/github.com/rest-mail/go-mtasts)

MTA-STS ([RFC 8461]) policy discovery, caching and enforcement for a sending
MTA, in Go. Standard library only: no external dependencies.

MTA-STS (SMTP MTA Strict Transport Security) lets a recipient domain declare
that senders must reach its mail servers over authenticated TLS. A sender
discovers the policy by reading the recipient's `_mta-sts.<domain>` TXT record,
which carries a short policy id, and then fetching the policy file from
`https://mta-sts.<domain>/.well-known/mta-sts.txt`. The policy names the MX
hosts allowed to receive mail and a mode: `enforce`, `testing` or `none`.

Under `enforce`, the sender must negotiate STARTTLS with an MX host that the
policy names and that presents a certificate valid for that host; otherwise
delivery is deferred rather than sent in the clear. Discovery fails open
(RFC 8461 §5): with no policy cached, a missing or invalid record, a failed
fetch or an unparseable policy all fall back to ordinary opportunistic TLS, so
a broken policy never blocks mail.

## Contents

- [Install](#install)
- [Packages](#packages)
- [Quick start](#quick-start)
- [Features](#features)
- [What the library does and what the host must do](#what-the-library-does-and-what-the-host-must-do)
- [RFC conformance](#rfc-conformance): [the checklist](#the-rfc-checklist), [what it does not do](#what-it-does-not-do), [badges and coverage](#badges-and-coverage), [tests](#tests)
- [Changelog](#changelog)
- [Licence](#licence)

## Install

```sh
go get github.com/rest-mail/go-mtasts@latest
```

The module declares go 1.25.

## Packages

| Import path | What it holds |
|-------------|---------------|
| `github.com/rest-mail/go-mtasts/pkg/mtasts` | The whole public API: `Policy`, `ParsePolicy`, the `Mode*` values and `Version`; `Resolver`, `NewResolver`, `LookupTXTFunc`, `FetchPolicyFunc`, `TXTName` and `PolicyURL`; `ErrNoPolicy` and its reasons `ErrNoRecord`, `ErrPolicyFetch` and `ErrPolicyInvalid`; `Fetcher` and `HTTPFetch`; `Evaluate`, `EvalInput` and `EnforceError`. |
| `pkg/mtasts/internal/txtrecord` | The `_mta-sts` TXT record grammar (RFC 8461 §3.1). Internal: not importable. |

Upgrading from v0.4 or earlier: the root package is gone. Import
`github.com/rest-mail/go-mtasts/pkg/mtasts`; the package is still named
`mtasts` and every name is unchanged. [CHANGELOG.md](CHANGELOG.md#050---2026-10-26)
has the full old-to-new table.

## Quick start

Discover a domain's policy, then judge one delivery attempt against it. In
production, use `mtasts.NewResolver()` as it is: it reads real TXT records and
fetches the policy over verified HTTPS. Here in-memory DNS and HTTPS keep the
example offline.

```go
package main

import (
	"context"
	"fmt"

	"github.com/rest-mail/go-mtasts/pkg/mtasts"
)

func main() {
	r := mtasts.NewResolver()

	// Inject in-memory DNS and HTTPS so this runs with no network. In
	// production, leave NewResolver's defaults in place.
	r.LookupTXT = func(_ context.Context, _ string) ([]string, error) {
		return []string{"v=STSv1; id=20260101T000000Z"}, nil
	}
	r.FetchPolicy = func(_ context.Context, _ string) ([]byte, error) {
		return []byte("version: STSv1\nmode: enforce\n" +
			"mx: mail.example.com\nmx: *.mx.example.com\nmax_age: 604800\n"), nil
	}

	policy, err := r.Resolve(context.Background(), "example.com")
	if err != nil {
		// ErrNoPolicy (errors.Is says why): fall back to opportunistic TLS.
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
		// *EnforceError is temporary: retry later rather than bounce.
		fmt.Println("MTA-STS enforce failed:", err)
	}
}
```

`Example` in [`pkg/mtasts/example_test.go`](pkg/mtasts/example_test.go) runs
the same round trip, and `ExampleEvaluate_traverse` walks a domain's MX hosts
in preference order, moving on after each enforce failure.

## Features

| Feature | RFC | API |
|---------|-----|-----|
| Discovery: the `_mta-sts` TXT record, then the HTTPS policy file | RFC 8461 §3.1, §3.3 | `Resolver.Resolve`, `TXTName`, `PolicyURL` |
| TXT record checked against the RFC's grammar; records not beginning `v=STSv1;` discarded; repeated fields ignored after the first | RFC 8461 §3.1, §3.2 | `Resolver.Resolve` |
| Policy file parser: lenient about layout and unknown keys, strict about the fields an enforcement decision needs; first value wins for repeated fields | RFC 8461 §3.2 | `ParsePolicy` |
| Cache keyed by the policy id, for `max_age` from when the fetch completed; `max_age: 0` applies without caching | RFC 8461 §3.2, §5.1 | `Resolver` |
| Daily refresh of a cached policy even when its id is unchanged | RFC 8461 §3.3, §10.2 | `Resolver` |
| A valid cached policy stays in force through discovery failures until it expires | RFC 8461 §3.1, §3.3, §10.2 | `Resolver` |
| Failed fetches retried no sooner than every 5 minutes per policy id | RFC 8461 §3.3 | `Resolver.NegativeTTL` |
| Why there is no policy, for a TLS-RPT reporter | RFC 8461 §6, RFC 8460 §4.3.2.2 | `ErrNoRecord`, `ErrPolicyFetch`, `ErrPolicyInvalid` |
| A hook for failed refreshes of a cached policy, to alert an administrator | RFC 8461 §3.3, §10.2 | `Resolver.RefreshFailed` |
| Policy fetch: HTTPS only, verified certificate, SNI, TLS 1.2 or later with RFC 7525 cipher suites, no redirects, no HTTP caching, `text/plain` only, 64 KiB and 10 s limits | RFC 8461 §3.2, §3.3, §7; RFC 7525 §4 | `Fetcher`, `HTTPFetch` |
| MX matching: exact host, or one leading `*.` label, label by label and case-insensitively | RFC 8461 §4.1 | `Policy.MatchesMX`, `Policy.MatchesCert` |
| Enforcement of one delivery attempt, with a temporary error | RFC 8461 §5, §5.1 | `Evaluate`, `EnforceError` |
| Injectable DNS, HTTPS, clock, dialer and root CAs for tests without a network | | `Resolver.LookupTXT`, `Resolver.FetchPolicy`, `Resolver.Now`, `Fetcher.DialContext`, `Fetcher.RootCAs` |

## What the library does and what the host must do

Each area below says what go-mtasts handles and what stays with the host, the
sending MTA that calls it. The [checklist](CHECKLIST.md) records these
boundaries row by row.

### Discovery and caching

The library:

- Reads the `_mta-sts.<domain>` TXT record and picks the one record beginning
  `v=STSv1;`. Any other number of such records, or one that breaks the grammar,
  means the domain has no policy.
- Serves a cached policy while its `max_age` has not run out and the published
  id is unchanged, and otherwise fetches and parses the policy file. The id is
  compared for equality only. A cached policy is fetched again once a day even
  when its id is unchanged, so it is refreshed long before a long `max_age`
  runs out.
- Keeps serving a valid cached policy when the TXT lookup or the fetch fails,
  whatever id the record now carries, until the policy expires. It reports the
  failure to `RefreshFailed` (if set) unless the cached mode is `none`.
- Remembers a failed fetch or parse for `NegativeTTL` (5 minutes by default
  and at least) after the attempt finishes, so a broken or blocked policy host
  is not probed for every message. A newly published id is fetched at once.
- Checks the clock again after each DNS and HTTPS call, so a policy that
  expired while discovery waited is not applied.
- Returns an error wrapping `ErrNoPolicy` when no policy applies, and with it
  the reason: `ErrNoRecord`, `ErrPolicyFetch` (the fetch's own error stays in
  the chain) or `ErrPolicyInvalid`, or a DNS error.
- Refuses a recipient domain that is not a DNS name, such as an address literal
  or text holding `/`, `@` or `:`, and never looks at a parent zone.
- Works as a zero value: a `Resolver{}` uses the real network, as
  `NewResolver` does.

The host:

- Chooses the Policy Domain: the recipient's domain, or the smart host's
  domain when it relays through one. It passes the domain in A-label form
  (see [#41](https://github.com/rest-mail/go-mtasts/issues/41)).
- Falls back to opportunistic TLS when `Resolve` returns an error.
- Sets `RefreshFailed` to log or alert on failed refreshes.

### Fetching the policy

The library (`Fetcher`, and `HTTPFetch`, which `NewResolver` uses):

- Fetches only over `https`, verifying the certificate against the system
  roots (or `Fetcher.RootCAs`) for the policy host, with SNI. Only subject
  alternative names count.
- Requires TLS 1.2 or later and, over TLS 1.2, offers only forward-secret
  ECDHE suites with AES or ChaCha20, whatever `GODEBUG` or the main module's
  `go` line say.
- Refuses redirects, any status but 200, and any media type but `text/plain`
  (parameters ignored).
- Refuses a body over 64 KiB rather than truncating it, and gives up after 10
  seconds.
- Opens a new connection for every fetch and closes it afterwards.

The host:

- Leaves `Fetcher.Insecure` and `HTTPFetch`'s `insecure` false in production.
  They skip certificate checks and allow `http` for development deployments.

### Applying the policy

The library:

- `Evaluate` takes the mode from the discovered `Policy.Mode`. Under `enforce`
  it returns an `*EnforceError` unless the MX host is named by the policy,
  STARTTLS succeeded and the certificate was valid for the host. `testing`,
  `none` and no policy never block.
- `EnforceError.Temporary` reports true: an enforce failure is a reason to
  retry, not to bounce.
- `Policy.MatchesMX` matches a host against the policy's patterns; a host that
  is not a DNS name matches nothing. `Policy.MatchesCert` compares a
  certificate's DNS names with the patterns, for offline analysis. It does not
  verify the certificate chain.

The host:

- Opens the SMTP connection: negotiates STARTTLS with SNI, verifies the MX
  certificate, and tells `Evaluate` the outcome through `EvalInput`.
- Tries the domain's MX hosts in preference order and calls `Evaluate` for each
  attempt.
- Retries an enforce failure later, and before giving up on a message checks
  DNS for an updated policy (RFC 8461 §5).
- Sets `EvalInput.AllowInsecureDowngrade` only where certificate verification
  is switched off on purpose, such as a test deployment, or when sending a
  TLS-RPT report (RFC 8460 §3). Its zero value fails closed.

## RFC conformance

### The RFC checklist

[CHECKLIST.md](CHECKLIST.md) lists every requirement RFC 8461 places on a
sending MTA, item by item, with the tests that cover each one, followed by the
sender's side of RFC 8460 (TLS-RPT). Requirements on publishers, on SMTP
transport and on the host's queue are listed too, as `n/a` rows that say whose
duty they are.

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

[`internal/checklist`](internal/checklist/main.go) checks one against the
other in CI. It is the same program as the other `go-*` libraries'.
`go run ./internal/checklist [-file CHECKLIST.md] [package dir ...]` scans the
`_test.go` files of the given package directories (default `.`) and fails
when:

- an ID is used twice, or a row is malformed;
- an item names no test and is not marked `n/a`;
- an item lists a test that does not exist, or that does not name the item;
- a test names an item that does not exist, is `n/a`, or does not list it;
- a `Test` or `Fuzz` function names no item (`Example` functions may).

CI runs it on the two packages that hold tests:

```sh
go run ./internal/checklist pkg/mtasts pkg/mtasts/internal/txtrecord
```

### What it does not do

Some gaps are deliberate, and go-mtasts will not fill them. Others are planned,
each with an issue. The checklist records the RFC's requirements among them as
`n/a` rows with the reason.

#### Not supported, by design

| Area | What go-mtasts does | Why |
|------|---------------------|-----|
| TLS-RPT (RFC 8460) | No reporting: it neither discovers reporting policies nor writes or sends reports. It gives a reporter the reason there is no policy (`ErrNoRecord`, `ErrPolicyFetch`, `ErrPolicyInvalid`), failed refreshes (`RefreshFailed`) and why an attempt failed (`EnforceError`). | Reporting needs a store for a day's results, a daily job and a mail or HTTPS sender with DKIM signing. That is the MTA's machinery; REST Mail's server sends and receives TLS-RPT itself. |
| Revocation | The policy host's certificate is not checked for revocation (OCSP, CRLs). | RFC 8461 makes it optional, Go's `crypto/tls` does none, and a check that cannot reach its responder would have to fail open anyway. |
| SMTP | No SMTP connection: STARTTLS, SNI, the TLS version and the MX certificate check belong to the caller, which reports the outcome to `Evaluate`. | The MTA already owns its SMTP client and its TLS settings; a second one here would only disagree with it. |
| DANE (RFC 7672) | Not implemented. A nil from `Evaluate` only means MTA-STS does not block; it never overrides a DANE failure. | DANE needs a DNSSEC-validating resolver and is a separate protocol. RFC 8461 §2 says MTA-STS must not override a failing DANE validation, and only a sender that runs both can apply that. |
| Delivery queue | No queue, retries or bounces, and no choice of Policy Domain for a smart host. | These are the MTA's delivery loop; the library answers for one domain and one attempt at a time. |

#### Not planned

| Area | What go-mtasts does |
|------|---------------------|
| Publishing | Nothing for the Policy Domain's side: it does not write policy files or TXT records, or serve the well-known URL. The library is for senders. |

#### Planned

| Gap | Issue |
|-----|-------|
| The resolver never drops expired cache entries, so its memory grows with every recipient domain it has seen. | [#39](https://github.com/rest-mail/go-mtasts/issues/39) |
| The cache lives in memory only, so a restart drops every cached policy and reopens the downgrade window. | [#40](https://github.com/rest-mail/go-mtasts/issues/40) |
| A recipient domain given as U-labels gets no policy instead of being converted to A-labels. | [#41](https://github.com/rest-mail/go-mtasts/issues/41) |

### Badges and coverage

The badges at the top are checked in CI. `TestReadmeChecklistBadge` in
`internal/checklist` runs the checker on the directories CI passes it and
compares the count: mapped rows over all rows, with the `n/a` rows in the
denominator, so the badge never claims more than the tests prove. The coverage
badge shows the floor CI enforces, not a measured figure; the workflow fixtures
in [`.github/tests`](.github/tests) check that it matches the pinned gate. Each
CI run prints the measured statement coverage in its `RFC proof` log. The lines
left uncovered on purpose are listed, each with a reason, in
[COVERAGE.md](COVERAGE.md).

CI runs go-spf's reusable
[`rfc-verification.yml`](https://github.com/rest-mail/go-spf/blob/7d291c08d310b9c62afc287e75a534a39150fafb/.github/workflows/rfc-verification.yml),
pinned to that commit: build, vet, golangci-lint, race tests with at least 95%
statement coverage, the checklist and 30 seconds of each fuzz target. The
required `Build & Test` check passes only when it and the workflow fixtures
both succeed.

### Tests

```sh
go test -race ./...                 # all tests, no network
go run ./internal/checklist pkg/mtasts pkg/mtasts/internal/txtrecord
go test -run='^$' -fuzz='^FuzzParsePolicy$' -fuzztime=30s ./pkg/mtasts
python3 -m unittest discover -s .github/tests   # what CI passes the shared proof
```

Three fuzz targets run in CI: `FuzzParsePolicy` in `pkg/mtasts` (any policy
body; an accepted policy is valid and parses again as itself when written out),
`FuzzParseTXTRecord` in `pkg/mtasts/internal/txtrecord` (any TXT record; an
accepted id is valid and came from a US-ASCII record led by `v=STSv1`) and
`FuzzMatchesMX` in `pkg/mtasts` (any pattern and host; a match ignores case and
a trailing dot, and a wildcard covers exactly one label). Their seeds are in
the targets, and inputs that once failed are kept there or in
`pkg/mtasts/testdata/fuzz`.

The RFC's own examples are tests: the policy of §3.2, the TXT record and
policy of Appendix A run through discovery, and the wildcard examples of §4.1.
The HTTPS fetch is tested against policy hosts served from memory with
certificates made per test (wrong name, untrusted, expired, common name only,
wildcards, TLS 1.1), and the default TXT lookup against an in-memory DNS
server (strings joined, CNAME chains followed). No test touches the network.
Differential tests check MX matching against
[foxcpp/go-mtasts](https://github.com/foxcpp/go-mtasts) (MIT), on fixed vectors
and under the fuzzer, listing each place where the two disagree on purpose and
why. foxcpp/go-mtasts and golang.org/x/net are test-only dependencies; the
library does not import them.

## Changelog

Recent releases; see [CHANGELOG.md](CHANGELOG.md) for the complete history.

### v0.5.0 (2026-10-26)

The library moves into `pkg/mtasts` and the root package is gone (breaking;
the changelog has a migration table). Names and behaviour are unchanged.

### v0.4.0 (2026-10-24)

`Resolve` says why there is no policy: `ErrNoRecord`, `ErrPolicyFetch` or
`ErrPolicyInvalid`, wrapped with `ErrNoPolicy`, for a TLS-RPT reporter.

### v0.3.1 (2026-10-22)

The policy fetch names its RFC 7525 cipher suites, and cache lifetimes are
checked again after DNS and HTTPS calls. The checklist covers the publisher,
SMTP and queue duties too.

### v0.3.0 (2026-10-17)

Checked against RFC 8461 item by item: cached policies refresh daily, with a
`RefreshFailed` hook; `max_age: 0` is valid; mx patterns and TXT extension
fields are validated; repeated TXT fields are ignored after the first;
certificate matching ignores the subject CN. Adds `Fetcher` and
`EnforceError.Temporary`, the RFC checklist, a 95% coverage gate and fuzzing.

### v0.2.1 (2026-07-25)

`Resolver.NegativeTTL`: failed fetches are not retried for 5 minutes per policy
id. A strict `_mta-sts` TXT parse, label-based wildcard MX matching and
`Content-Type` validation.

### v0.2.0 (2026-07-25)

`Evaluate` takes the mode from the discovered `Policy.Mode`, so enforcement
fails closed (breaking: `EvalInput.Mode` is removed, `AllowInsecureDowngrade`
is new). The policy fetch is HTTPS only.

### v0.1.1 (2026-07-23)

The module is renamed `github.com/rest-mail/go-mtasts`.

### v0.1.0 (2026-07-23)

First release: MTA-STS (RFC 8461) policy discovery, caching and enforcement.

## Licence

[MIT](LICENSE) © 2026 rest-mail

[RFC 8461]: https://www.rfc-editor.org/rfc/rfc8461

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Note: pre-1.0, breaking changes may ship in a minor release.

## [Unreleased]

go-mtasts now meets the standard of rest-mail/rest-mail-server#374: an RFC
8461 checklist checked in CI, a 95% coverage gate, fuzzing, the RFC's examples
as tests, and differential tests of MX matching against foxcpp/go-mtasts.
Writing the checklist and fuzzing found the bugs fixed below. The module is
v0.x and its only user is REST Mail's server, so where compatibility would
cost anything this is a clean break.

### Added

- README badges for the enforced ≥95% coverage gate and the checklist's
  mapped/total requirement count. CI checks the count against the validated
  checklist so it cannot silently drift.
- **`Fetcher`**, the policy fetch `HTTPFetch` now wraps, with an injectable
  `DialContext` and `RootCAs` so a test can serve a policy host from memory.
  It refuses TLS below 1.2 and opens a new connection for every fetch
  (RFC 8461 §3.3, §7.2).
- **Daily refresh.** `Resolve` fetches a cached policy again once a day even
  when its id is unchanged, instead of waiting for `max_age` to run out
  (RFC 8461 §3.3, §10.2). A refresh that fails keeps the cached policy.
- **`Resolver.RefreshFailed`**, called when discovery fails while a cached
  policy stays in force (unless its mode is `none`), so the caller can alert
  an administrator (RFC 8461 §3.3, §10.2).
- **`EnforceError.Temporary`**, which reports true: an enforce failure must
  not bounce a message (RFC 8461 §5, §5.1).

### Changed

- **`max_age: 0` is valid.** RFC 8461 §3.2 allows any non-negative value; the
  policy is applied and not cached. It used to make the policy invalid.
  `max_age` must also be at most 10 digits.
- **Repeated TXT fields are ignored after the first.** RFC 8461 §3.2 says so
  for TXT records as well as policy files; a record with a second `v=` or
  `id=` used to be refused.
- **TXT records are counted after discarding those not beginning
  `v=STSv1;`** (RFC 8461 §3.1). Two such records, one of them invalid, used to
  yield the valid one's id; now the domain has no policy.
- **A `Content-Type` of `text/plain` with a malformed parameter is accepted**:
  RFC 8461 §3.2 says to ignore the parameters.

### Fixed

- **mx patterns are validated.** A policy whose `mx` is not a domain name
  (optionally behind `*.`) in A-label form, including an empty `mx:` line, is
  invalid (RFC 8461 §3.2); it used to be enforced with the bad pattern, or
  with an empty one silently dropped.
- **TXT extension fields are validated** against the sts-extension grammar
  (RFC 8461 §3.1); any `name=value` text used to pass.
- **`MatchesCert` ignores the subject common name.** RFC 8461 §4.2 requires a
  subject alternative name DNS-ID; a certificate naming the host only in its
  CN used to match.
- **`MatchesMX` matches nothing to a host that is not a DNS name**, so
  `*.example.com` no longer matches a host literally named `*.example.com`,
  and nothing to a pattern `ParsePolicy` would refuse, so a bare `*` in a
  hand-built `Policy` no longer matches every single-label host, nor a host
  padded with spaces its trimmed form. Found by the new tests and the fuzzer.
- **`Resolve` refuses a recipient domain that is not a DNS name** (an address
  literal, or text holding `/`, `@` or `:`) instead of splicing it into the
  policy URL, where it could name another host, port or path (RFC 8461 §3.4).
- **The policy fetch no longer leaves an idle connection open** after each
  call.

### What the server will feel

- One extra policy fetch per recipient domain per day, from the daily refresh.
- Domains publishing `max_age: 0` are now enforced; domains with an invalid
  `mx` pattern, a malformed TXT extension field, or a second, invalid
  `v=STSv1` record now have no policy (fail open), as RFC 8461 says.
- `RefreshFailed` is opt-in; set it to log refresh failures.

## [0.2.1] - 2026-07-25

### Added

- **resolver:** new `NegativeTTL` field on `Resolver` for negative caching of
  failed policy fetches. A fetch or parse failure for a given `(domain, id)` is
  now remembered so repeated `Resolve` calls within the window do not re-probe a
  broken or blocked policy host on every outbound message. Previously only
  successful policies were cached, so the next `Resolve` for the same domain
  re-fetched immediately and amplified load against a down or hostile host; a
  newly published policy `id` is still fetched immediately. Defaults to 5 minutes
  and is floored there — a shorter value is raised to 5 minutes so the re-probe
  amplifier the negative cache exists to close cannot be reopened
  (RFC 8461 §3.3).

### Fixed

- **resolver:** validate the HTTPS policy response `Content-Type`. The policy
  fetch previously checked only the status code and size, so a response served
  as `text/html` (a captive portal or error page) or any other media type was
  read and handed to `ParsePolicy`, which is lenient about unknown lines and
  could parse a stray body into an unintended policy. `HTTPFetch` now requires
  the media type to be `text/plain` (matched case-insensitively, parameters such
  as `charset` ignored) per RFC 8461 §3.2 and rejects anything else — including a
  missing or unparseable `Content-Type` — as a fetch failure. (#12)
- **resolver:** validate the `_mta-sts` TXT discovery record against the
  RFC 8461 §3.1 grammar instead of parsing it leniently. The old parser accepted
  fields in the wrong order (`id=…; v=STSv1`), whitespace inside the `v=STSv1`
  and `id=` tokens (`v = STSv1`), a repeated `v=`, and any `id` value regardless
  of character set or length. It now requires the record to lead with the exact
  `v=STSv1` token, carry exactly one `id=` whose value is `1*32(ALPHA / DIGIT)`,
  and reject a duplicated version field; a malformed record is treated as "no
  policy". This closes a discovery/caching hole where an attacker- or
  typo-shaped TXT record could still drive policy resolution. (#11)
- **policy:** match a wildcard MX pattern by DNS label instead of by counting
  dots and matching a suffix. The old check let `*.example.com` match
  `.example.com` — a name with an empty leading label — because that name ends in
  `.example.com` and carries one extra dot, satisfying the count even though the
  wildcard label was empty. Matching now splits host and pattern into labels,
  requires an equal label count, lets a leading `*` match exactly one non-empty
  label, and compares every remaining label exactly. A wildcard covers exactly
  one non-empty label per RFC 8461 §4.1, so `example.com`, `a.b.example.com`, and
  `.example.com` are all now correctly rejected against `*.example.com`. (#13)
- **resolver:** make a zero-value `Resolver` usable instead of a nil-panic trap.
  `Resolve` called the `LookupTXT`/`FetchPolicy` hooks directly, so a `Resolver`
  built as a literal (`mtasts.Resolver{}`) rather than via `NewResolver`
  panicked on first use. The nil fields now fall back to the real-network
  defaults (`net.DefaultResolver.LookupTXT` and a verified HTTPS fetch), exactly
  as `Now` already defaulted to `time.Now`. (#14)
- **resolver:** reject an oversized policy body instead of silently truncating
  it. The HTTPS fetch capped the read at 64 KB and returned the truncated bytes
  with no error, so the library could enforce a different policy than the one
  published (e.g. a trailing `mode: none` dropped, leaving an `mode: enforce`
  prefix in force). An oversize body is now treated as no usable policy
  (RFC 8461 §3.3). (#9)

## [0.2.0] - 2026-07-25

A security and correctness release. All five fixes harden policy handling and
enforcement against fail-open behaviour. Includes one breaking change to the
exported API.

### Breaking

- `Evaluate` now derives the enforcement mode from the discovered
  `Policy.Mode`, not from a caller-supplied field. The exported field
  `EvalInput.Mode` has been **removed**. A new `EvalInput.AllowInsecureDowngrade`
  (`bool`) replaces the old mode-override as the sole downgrade path; its zero
  value fails closed, so an `enforce` policy can no longer be silently disabled
  by a caller that forgets to restate the mode. To downgrade an `enforce` policy
  to report-only in a dev/test deployment, set `AllowInsecureDowngrade: true`.
  Callers that previously passed `Mode: policy.Mode` should simply drop the
  field. (#20)

### Fixed

- **enforce:** gate `Evaluate` on the published `Policy.Mode` rather than a
  redundant input field whose zero value skipped every check. Previously a
  caller that populated the discovered policy but left the mode field unset
  delivered in the clear to an `enforce` domain (fail-open). An `enforce` policy
  with an MX mismatch, missing STARTTLS, or an invalid certificate now fails
  closed (RFC 8461 §5). (#20)
- **resolver:** retain a cached `enforce` policy when policy discovery
  transiently fails, instead of dropping to "no policy" and allowing insecure
  delivery. (#16)
- **resolver:** pin policy fetching to HTTPS and reject non-HTTPS policy URLs
  (RFC 8461 §3.3). (#17)
- **policy:** apply first-wins semantics for duplicate non-`mx` policy fields
  (RFC 8461 §3.2). (#18)
- **policy:** validate that `max_age` is within the permitted range and reject
  integer overflow (RFC 8461 §3.2). (#19)

## [0.1.1] - 2026-07-23

### Changed

- Rename the module to `github.com/rest-mail/go-mtasts`. (#2)
- Install github-guard git hooks. (#1)

## [0.1.0] - 2026-07-23

### Added

- Initial release: MTA-STS (RFC 8461) policy discovery, caching, and
  enforcement.

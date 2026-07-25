# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is `0`, a minor bump may carry a breaking change to the exported API.

## Unreleased

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
- **resolver:** negative-cache a failed policy fetch/parse per version id so a
  broken or blocked policy host is not re-probed on every outbound message.
  Previously only successful policies were cached; a fetch or parse failure left
  no trace, so the next `Resolve` for the same domain immediately re-fetched,
  amplifying load against a down or hostile policy host. A failure for a given
  `(domain, id)` is now remembered for `NegativeTTL` (default 5 minutes) and the
  re-fetch suppressed until it elapses, while a newly published `id` is fetched
  immediately (RFC 8461 §3.3). (#15)

## v0.2.0

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

## v0.1.1

### Changed

- Rename the module to `github.com/rest-mail/go-mtasts`. (#2)
- Install github-guard git hooks. (#1)

## v0.1.0

### Added

- Initial release: MTA-STS (RFC 8461) policy discovery, caching, and
  enforcement.

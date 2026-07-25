# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is `0`, a minor bump may carry a breaking change to the exported API.

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

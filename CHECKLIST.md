# RFC 8461 checklist

Every requirement [RFC 8461](https://www.rfc-editor.org/rfc/rfc8461) (MTA-STS)
places on a sending MTA, item by item, with the tests that cover it, followed
by the sender's side of [RFC 8460](https://www.rfc-editor.org/rfc/rfc8460)
(TLS-RPT), which the library does not implement. The list takes in every MUST,
MUST NOT, SHOULD, SHOULD NOT, RECOMMENDED and NOT RECOMMENDED that applies to a
sender, the MAYs the library implements, and the normative behaviour that
carries no keyword (level "Normative"), such as the grammars of the TXT record
and the policy file. Requirements on Policy Domains and Policy Hosts are left
out, except where a sender checks them. A section number alone is RFC 8461.

An item that does not apply to a library (because it is the sending MTA's
delivery loop, say) says "n/a" and why. CI checks this file against the tests
with `go run ./internal/checklist`; the format is described in the
[README](README.md#the-rfc-checklist).

## The TXT record (§3.1)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| MTASTS-TXT-01 | 3.1 | Normative | Look the record up as a TXT record at `_mta-sts.` and the Policy Domain. | `TestTXTNameAndPolicyURL`, `TestRFC8461AppendixA` |
| MTASTS-TXT-02 | 3.1 | MUST | The record begins with the `v=STSv1` field, matched case-sensitively; only STSv1 is supported. | `TestParseTXTID`, `TestParseTXTIDStrict` |
| MTASTS-TXT-03 | 3.1 | MUST | The record is US-ASCII fields of the ABNF: `id=` is 1*32(ALPHA / DIGIT), an extension is an sts-ext-name `=` an sts-ext-value, whitespace only around `;`; any other record is invalid. | `TestParseTXTIDStrict`, `TestTXTRecordGrammar`, `FuzzParseTXTRecord` |
| MTASTS-TXT-04 | 3.1 | MUST | Discard records that do not begin with `v=STSv1;`; if not exactly one remains, or it is invalid, the domain has no available policy. | `TestParseTXTID`, `TestTXTRecordDiscardRule` |
| MTASTS-TXT-05 | 3.1 | MUST | A record of several strings is read as the strings joined without spaces. | `TestDefaultResolverTXT` |
| MTASTS-TXT-06 | 3.1, 8.2 | MUST | Follow a CNAME at `_mta-sts` (directly or through other CNAMEs) to the TXT record. | `TestDefaultResolverTXT` |
| MTASTS-TXT-07 | 3.2 | MUST | Accept a valid record with fields this specification does not define, ignoring them. | `TestParseTXTID`, `TestTXTRecordGrammar` |
| MTASTS-TXT-08 | 3.2 | SHALL | When `v=` or `id=` is repeated, ignore every occurrence after the first. | `TestTXTRecordFirstWins` |
| MTASTS-TXT-09 | 3.1 | Normative | The id only says whether a policy changed: compare it with the cached id for equality, with no ordering between ids. | `TestResolveRefetchesWhenIDChanges`, `TestResolveIDHasNoOrder` |

## The policy file (§3.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| MTASTS-POL-01 | 3.2 | Normative | Fetch the policy with GET from `https://mta-sts.` + the Policy Domain + `/.well-known/mta-sts.txt`. | `TestTXTNameAndPolicyURL`, `TestRFC8461AppendixA`, `TestFetcherSendsGET` |
| MTASTS-POL-02 | 3.2 | SHOULD | Validate that the media type is `text/plain`, ignoring its parameters. | `TestHTTPFetchRejectsNonTextPlain`, `TestHTTPFetchAcceptsTextPlain` |
| MTASTS-POL-03 | 3.2 | Normative | The policy is `key: value` lines ended by LF or CRLF, with optional whitespace after the colon. | `TestParsePolicy`, `FuzzParsePolicy` |
| MTASTS-POL-04 | 3.2 | Normative | `version` is required and is `STSv1`, matched case-sensitively. | `TestParsePolicy`, `TestParsePolicyCaseSensitive` |
| MTASTS-POL-05 | 3.2 | Normative | `mode` is required and is `enforce`, `testing` or `none`, matched case-sensitively. | `TestParsePolicy`, `TestParsePolicyCaseSensitive` |
| MTASTS-POL-06 | 3.2 | Normative | `max_age` is required: 1 to 10 digits, a non-negative number of seconds of at most 31557600. | `TestParsePolicyMaxAgeRange`, `FuzzParsePolicy` |
| MTASTS-POL-07 | 3.2 | Normative | `mx` is required at least once, unless the mode is `none`. | `TestParsePolicy` |
| MTASTS-POL-08 | 3.2 | MUST | Each mx pattern has its own `mx:` line, and is a domain name, optionally behind `*.`. | `TestParsePolicyMXPatterns`, `TestParsePolicyDuplicateFieldsFirstWins`, `FuzzParsePolicy` |
| MTASTS-POL-09 | 3.2 | MUST | An internationalized mx pattern is given as its A-label, not its U-label. | `TestParsePolicyMXPatterns` |
| MTASTS-POL-10 | 3.2 | MUST | Accept a valid policy with fields this specification does not define, ignoring them. | `TestParsePolicyUnknownFields` |
| MTASTS-POL-11 | 3.2 | SHALL | When a field other than `mx` is repeated, ignore every occurrence after the first. | `TestParsePolicyDuplicateFieldsFirstWins` |
| MTASTS-POL-12 | 3.2, A | Normative | The example policies of §3.2 and Appendix A parse as published. | `TestRFC8461Section32Example`, `TestRFC8461AppendixA` |

## Fetching the policy (§3.3, §7)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| MTASTS-FETCH-01 | 3.3 | MUST | Fetch the policy over HTTPS, never in cleartext. | `TestHTTPFetchRejectsCleartext`, `TestFetcherRejectsOtherSchemes` |
| MTASTS-FETCH-02 | 3.3 | MUST | The policy host's certificate is valid for the `mta-sts` DNS-ID, chains to a root CA the sender trusts, and has not expired. | `TestFetcherVerifiesCertificate`, `TestHTTPFetchVerifiesCertificate` |
| MTASTS-FETCH-03 | 3.3 | Normative | Match only DNS-IDs (not the subject common name); a wildcard may only be the whole left-most label. | `TestFetcherMatchesOnlyDNSIDs` |
| MTASTS-FETCH-04 | 3.3 | MAY | Check the policy host's certificate for revocation (OCSP, CRLs). | n/a: not supported; Go's crypto/tls does no revocation checking, and RFC 8461 leaves it optional. |
| MTASTS-FETCH-05 | 3.3 | Normative | A policy is valid only from a 200 (OK) response. | `TestFetcherRequiresStatus200` |
| MTASTS-FETCH-06 | 3.3 | MUST NOT | Follow HTTP 3xx redirects. | `TestHTTPFetchDoesNotFollowRedirect` |
| MTASTS-FETCH-07 | 3.3, 8.2 | MUST NOT | Use HTTP caching when fetching a policy. | `TestFetcherDoesNotCache` |
| MTASTS-FETCH-08 | 3.3 | SHOULD | After a failed fetch, try again no sooner than five minutes later for the same version id. | `TestResolveNegativeCachesFailedFetch`, `TestResolveNegativeCacheDoesNotSuppressNewID`, `TestResolveNegativeCacheConcurrent`, `TestResolveNegativeTTLConfigurable` |
| MTASTS-FETCH-09 | 3.3 | MAY | Impose a timeout and a limit on the size of the body (64 KB suggested); a larger body is not a policy. | `TestHTTPFetchRejectsOversizedPolicy`, `TestHTTPFetchAcceptsMaxSizedPolicy`, `TestFetcherHonoursContext`, `TestFetcherBodyReadError` |
| MTASTS-FETCH-10 | 3.3 | MUST | With a valid TXT record but no policy fetched and none cached, deliver as though the domain had no MTA-STS. | `TestResolveFailOpen`, `TestZeroValueResolverDoesNotPanic` |
| MTASTS-FETCH-11 | 3.3 | MUST | When no live policy can be discovered but a valid cached one exists, apply the cached policy. | `TestResolveRetainsCachedEnforceOnTransientFailure` |
| MTASTS-FETCH-12 | 3.3, 10.2 | SHOULD | Refresh cached policies before they expire (once a day is suggested); do not wait for a cached policy to expire before checking for an update. | `TestResolveRefreshesDaily` |
| MTASTS-FETCH-13 | 3.3, 10.2 | SHOULD | Alert administrators when refreshing a cached policy fails, unless its mode is `none`. | `TestResolveRefreshFailed` |
| MTASTS-FETCH-14 | 7.1 | MUST | The TLS SNI extension of the policy fetch names the Policy Host. | `TestFetcherSendsSNI` |
| MTASTS-FETCH-15 | 7.2 | MUST | Support TLS 1.2 or later: the fetch refuses older versions. | `TestFetcherRequiresTLS12` |
| MTASTS-FETCH-16 | 7.2 | SHOULD | Follow the TLS guidance of RFC 7525. | n/a: the fetch uses crypto/tls's defaults, which follow it (no SSL, no RC4, forward-secret AEAD suites first); the library sets only the minimum version. |

## Caching (§3, §3.2, §5.1)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| MTASTS-CACHE-01 | 3.2, 5.1 | SHOULD | Cache a policy for up to `max_age` seconds from when it was fetched; a `max_age` of 0 applies the policy without caching it. | `TestResolveCachesUntilMaxAge`, `TestStoreOversizedMaxAgeCachesInsteadOfExpiring`, `TestResolveMaxAgeZero` |
| MTASTS-CACHE-02 | 3, 5.1 | Normative | While the TXT record's id equals the cached policy's, use the cached policy without an HTTPS fetch; a new id means a new policy to fetch. | `TestResolveHappyPath`, `TestResolveCachesUntilMaxAge`, `TestResolveRefetchesWhenIDChanges`, `Example` |
| MTASTS-CACHE-03 | 3.1, 5.1 | Normative | The absence of a usable TXT record does not by itself remove a cached policy. | `TestResolveRetainsCachedEnforceOnTransientFailure` |
| MTASTS-CACHE-04 | 10.2 | SHOULD | Prefer `max_age` values as long as is practical. | n/a: advice to Policy Domains on the values they publish; the library caches whatever `max_age` a policy gives. |

## The Policy Domain (§3.4)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| MTASTS-DOM-01 | 3.4 | MUST | When sending through a smart host, treat the smart host's domain as the Policy Domain. | n/a: the caller chooses the Policy Domain; Resolve looks up the domain it is given. |
| MTASTS-DOM-02 | 3.4 | MUST NOT | For a mailbox at a subdomain, fetch a policy from the parent zone. | `TestResolveNoParentZone` |
| MTASTS-DOM-03 | 3.4 | Normative | An address literal has no policy; neither does any other recipient domain that is not a DNS name. | `TestResolveRejectsNonDomain` |

## Validating an MX host (§4, §4.1, §4.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| MTASTS-MX-01 | 4, 4.1 | MUST | Check that at least one of the policy's mx patterns matches the selected MX host. | `TestEvaluate`, `TestMatchesMX`, `Example` |
| MTASTS-MX-02 | 4.1 | Normative | Match names as RFC 6125 does: case-insensitively, label by label, with an absolute name's trailing dot ignored. | `TestMatchesMX`, `TestMatchesMXEdgeCases`, `TestDiffMatchesMX`, `FuzzMatchesMX` |
| MTASTS-MX-03 | 4.1 | Normative | A `*` matches exactly the whole left-most label: `*.example.com` matches `mail.example.com`, not `example.com` or `foo.bar.example.com`. | `TestMatchesMX`, `TestRFC8461Section41Examples`, `TestDiffMatchesMX`, `FuzzMatchesMX`, `ExampleParsePolicy` |
| MTASTS-MX-04 | 4, 4.2 | MUST | Check that the MX supports STARTTLS and presents a certificate valid for the host, unexpired and chained to a trusted root. | `TestEvaluate` |
| MTASTS-MX-05 | 4.2 | MUST | The certificate has a subject alternative name with a DNS-ID matching the host; the subject common name does not count. | `TestMatchesCert`, `TestCertNameWildcardCoversConcretePolicy` |
| MTASTS-MX-06 | 4.2 | MAY | Check the MX certificate for revocation. | n/a: the caller's TLS handshake verifies the certificate; Evaluate takes the outcome as CertValid. |
| MTASTS-MX-07 | 8.4 | Normative | Traverse the MX candidates as usual, treating one that fails validation as unreachable rather than filtering the list first. | n/a: the caller traverses the MX list; Evaluate judges one candidate at a time and its error is transient, so the caller moves on to the next. |

## Applying the policy (§2, §5)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| MTASTS-APPLY-01 | 5 | MUST NOT | Under `enforce`, deliver to a host that fails MX matching or certificate validation, or does not support STARTTLS. | `TestEvaluate`, `TestEvaluateGatesOnPolicyMode` |
| MTASTS-APPLY-02 | 5 | Normative | Under `testing`, deliver as though there were no validation failure. | `TestEvaluate`, `TestEvaluateGatesOnPolicyMode` |
| MTASTS-APPLY-03 | 5 | Normative | Under `none`, treat the Policy Domain as though it had no active policy. | `TestEvaluate`, `TestEvaluateGatesOnPolicyMode` |
| MTASTS-APPLY-04 | 5, 5.1 | MUST NOT | Permanently fail a message refused under `enforce` before checking DNS for a new policy; such failures SHOULD be treated as transient. | `TestEnforceErrorIsTransient` |
| MTASTS-APPLY-05 | 2 | MUST NOT | Let MTA-STS validation override a failing DANE validation. | n/a: the library does no DANE; Evaluate returning nil means only that MTA-STS does not block, and gives a caller nothing to override DANE with. |
| MTASTS-APPLY-06 | 5 | Normative | Apply only a valid, non-expired policy. | `TestResolveRetainsCachedEnforceOnTransientFailure`, `TestResolveCachesUntilMaxAge` |

## Reporting failures (§6)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| MTASTS-REP-01 | 6 | SHOULD | A sender that implements TLSRPT reports HTTPS fetch failures when a valid TXT record exists. | n/a: the library implements no TLSRPT (see the RFC 8460 section below). |
| MTASTS-REP-02 | 6 | SHOULD | A sender that implements TLSRPT reports fetch failures of any kind while a valid cached policy exists, unless its mode is `none`. | n/a: the library implements no TLSRPT; RefreshFailed tells the caller of exactly these failures. |
| MTASTS-REP-03 | 6 | SHOULD | A sender that implements TLSRPT reports MX hosts without STARTTLS or a valid certificate under the applied policy, unless its mode is `none`. | n/a: the library implements no TLSRPT; Evaluate's EnforceError gives the caller the reason. |

## RFC 8460 (TLS-RPT), the sender's side

The library implements no part of TLS-RPT: it neither discovers reporting
policies nor writes or sends reports. These items are here so that a reader
looking for them finds why. REST Mail's server receives TLS-RPT reports itself.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| TLSRPT-01 | RFC 8460 3 | Normative | Discover the reporting policy as a `v=TLSRPTv1` TXT record at `_smtp._tls.` and the Policy Domain. | n/a: the library implements no TLS-RPT. |
| TLSRPT-02 | RFC 8460 3 | MUST | Discard records not beginning `v=TLSRPTv1;`; unless exactly one remains, the domain does not implement TLSRPT. | n/a: the library implements no TLS-RPT. |
| TLSRPT-03 | RFC 8460 3 | MUST | Read a record of several strings as the strings joined without spaces, and accept valid records with unknown fields. | n/a: the library implements no TLS-RPT. |
| TLSRPT-04 | RFC 8460 3 | MUST | Deliver reports sent by SMTP despite TLS failures, without honouring MTA-STS or DANE failures (§5.3). | n/a: the library sends no reports. A caller delivering one sets EvalInput.AllowInsecureDowngrade. |
| TLSRPT-05 | RFC 8460 3 | MUST | DKIM-sign reports sent by SMTP as the reporting domain, without `l=`. | n/a: the library sends no reports. |
| TLSRPT-06 | RFC 8460 4 | MUST | Write the report's `policies` field as an array, even for one policy. | n/a: the library writes no reports. |
| TLSRPT-07 | RFC 8460 4.1 | SHOULD | Cover a full UTC day in each report. | n/a: the library writes no reports. |
| TLSRPT-08 | RFC 8460 4.3 | SHOULD | Give a `failure-reason-code` with `certificate-not-trusted` and `validation-failure` results. | n/a: the library writes no reports. |
| TLSRPT-09 | RFC 8460 4.4 | MUST | Write internationalized domains in reports as A-labels. | n/a: the library writes no reports. |
| TLSRPT-10 | RFC 8460 5.1, 5.2 | SHOULD | Name report files by the RFC's ABNF, ending `.json` or `.json.gz`, and compress them with gzip. | n/a: the library writes no reports. |
| TLSRPT-11 | RFC 8460 5.3 | MUST | Include the TLS-Report-Domain and TLS-Report-Submitter header fields in reports sent by mail. | n/a: the library sends no reports. |
| TLSRPT-12 | RFC 8460 5.4 | SHOULD | POST reports over HTTPS as `application/tlsrpt+gzip` or `application/tlsrpt+json`. | n/a: the library sends no reports. |
| TLSRPT-13 | RFC 8460 5.5 | SHOULD | Retry failed report delivery for up to 24 hours, with exponential backoff. | n/a: the library sends no reports. |

// Package mtasts discovers, caches, and enforces MTA-STS (RFC 8461) policies
// for outbound SMTP delivery.
//
// MTA-STS (SMTP MTA Strict Transport Security) lets a recipient domain publish
// a policy declaring that senders MUST reach its mail servers over
// authenticated TLS. A sending MTA discovers the policy by first reading the
// recipient's _mta-sts.<domain> TXT record — which carries a short policy id —
// and then, when that id is new, fetching the policy file over HTTPS from
// https://mta-sts.<domain>/.well-known/mta-sts.txt. The policy names the MX
// hosts allowed to receive mail and a mode: "enforce", "testing", or "none".
//
// When the mode is "enforce" the sender MUST negotiate STARTTLS to an MX host
// that is (a) named by the policy and (b) presents a certificate valid for that
// host; otherwise the message is deferred rather than delivered in the clear.
// Discovery fails open (RFC 8461 section 5) only when no policy is cached: a
// missing or invalid TXT record, a fetch error, or an unparseable policy fall
// back to ordinary opportunistic TLS, so a broken policy never blocks mail. A
// valid, non-expired cached policy is never dropped by a transient discovery
// failure, though — it stays in effect until its max_age elapses (RFC 8461
// sections 3.1 and 3.3), which defeats the section 10.2 downgrade attack of
// blocking the TXT response or the policy fetch.
//
// # Discovery and caching
//
// A [Resolver] performs discovery. [Resolver.Resolve] reads the TXT record,
// serves a cached policy while its max_age has not elapsed and the id is
// unchanged, and otherwise fetches and parses the HTTPS policy file. If that
// live discovery transiently fails while a non-expired policy is still cached,
// the cached policy is served rather than dropped. It returns the parsed
// [Policy] or [ErrNoPolicy]. [ParsePolicy] parses a policy file body on its own
// if the fetch is handled elsewhere.
//
// # Enforcement
//
// [Evaluate] applies a discovered policy to the observed TLS outcome of one
// delivery attempt, returning a deferrable [EnforceError] when an "enforce"
// policy is violated. [Policy.MatchesMX] reports whether a concrete MX hostname
// is named by the policy, using RFC 6125 matching: an exact host, or a single
// leading "*." wildcard label.
//
// # Testing without a network
//
// A Resolver's DNS and HTTPS steps are injectable through its LookupTXT,
// FetchPolicy, and Now fields, so discovery can be driven from in-memory data
// in tests, or pointed at an insecure fetch for a development deployment. See
// the package example.
package mtasts

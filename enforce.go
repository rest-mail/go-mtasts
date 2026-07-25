package mtasts

import "fmt"

// EnforceError reports that an MTA-STS "enforce" requirement was not met for a
// delivery attempt. It is a deferrable (transient) condition: the outbound
// queue should retry later rather than bounce the message, because a valid TLS
// path to the recipient may become available (cert renewal, MX repair, etc.).
type EnforceError struct {
	Domain string
	MXHost string
	Reason string
}

func (e *EnforceError) Error() string {
	return fmt.Sprintf("MTA-STS enforce: %s (domain=%s mx=%s)", e.Reason, e.Domain, e.MXHost)
}

// EvalInput captures the observed TLS outcome of a single SMTP delivery attempt
// to one MX host, to be judged against a discovered policy.
type EvalInput struct {
	// Policy is the discovered policy (nil means no policy was published). The
	// effective enforcement mode is Policy.Mode — the value published by the
	// recipient — not a caller-supplied override (RFC 8461 §5).
	Policy *Policy
	// Domain is the recipient domain (for diagnostics).
	Domain string
	// MXHost is the MX host the attempt connected to.
	MXHost string
	// STARTTLS is true when STARTTLS was negotiated successfully.
	STARTTLS bool
	// CertValid is true when the presented certificate chained to a trusted
	// root and was valid for MXHost.
	CertValid bool
	// AllowInsecureDowngrade, when true, downgrades an "enforce" policy to
	// report-only so a would-fail no longer blocks delivery. This is a
	// deliberate, dangerous opt-in for dev/test deployments where certificate
	// verification is globally disabled; it MUST NOT be set in production. When
	// false (the zero value), an "enforce" policy fails closed as RFC 8461 §5
	// requires — the safe default.
	AllowInsecureDowngrade bool
}

// Evaluate applies MTA-STS policy to a delivery attempt.
//
// The enforcement mode is taken from the discovered policy (Policy.Mode), never
// from a caller-supplied override: enforcement is a property of the recipient's
// published policy (RFC 8461 §5).
//
// It returns nil when delivery may proceed, and an *EnforceError (deferrable)
// when an "enforce" policy is violated. For "testing", "none", or no policy it
// always returns nil — those modes never block delivery (a "testing" would-fail
// is a reporting signal only, logged by the caller).
//
// Under "enforce" three conditions must all hold: the MX host must be named by
// the policy, STARTTLS must have succeeded, and the certificate must be valid
// for the MX host. Setting AllowInsecureDowngrade suppresses the block (a
// deliberate dev/test opt-in); its zero value fails closed.
func Evaluate(in EvalInput) error {
	// Gate on the policy's own mode. A nil policy (no policy published) or any
	// mode other than "enforce" never blocks delivery.
	if in.Policy == nil || in.Policy.Mode != ModeEnforce {
		return nil
	}
	if in.AllowInsecureDowngrade {
		return nil
	}
	fail := func(reason string) error {
		return &EnforceError{Domain: in.Domain, MXHost: in.MXHost, Reason: reason}
	}
	if len(in.Policy.MX) > 0 && !in.Policy.MatchesMX(in.MXHost) {
		return fail("MX host not named by policy")
	}
	if !in.STARTTLS {
		return fail("STARTTLS required but not established")
	}
	if !in.CertValid {
		return fail("certificate not valid for MX host")
	}
	return nil
}

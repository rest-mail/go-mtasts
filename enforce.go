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
	// Policy is the discovered policy (nil means no policy was published).
	Policy *Policy
	// Mode is the effective mode to apply. It normally equals Policy.Mode, but
	// the caller may downgrade "enforce" to "testing" (e.g. when certificate
	// verification is globally disabled for a dev/test deployment).
	Mode string
	// Domain is the recipient domain (for diagnostics).
	Domain string
	// MXHost is the MX host the attempt connected to.
	MXHost string
	// STARTTLS is true when STARTTLS was negotiated successfully.
	STARTTLS bool
	// CertValid is true when the presented certificate chained to a trusted
	// root and was valid for MXHost.
	CertValid bool
}

// Evaluate applies MTA-STS policy to a delivery attempt.
//
// It returns nil when delivery may proceed, and an *EnforceError (deferrable)
// when an "enforce" policy is violated. For "testing", "none", or no policy it
// always returns nil — those modes never block delivery (a "testing" would-fail
// is a reporting signal only, logged by the caller).
//
// Under "enforce" three conditions must all hold: the MX host must be named by
// the policy, STARTTLS must have succeeded, and the certificate must be valid
// for the MX host.
func Evaluate(in EvalInput) error {
	if in.Mode != ModeEnforce {
		return nil
	}
	fail := func(reason string) error {
		return &EnforceError{Domain: in.Domain, MXHost: in.MXHost, Reason: reason}
	}
	if in.Policy != nil && len(in.Policy.MX) > 0 && !in.Policy.MatchesMX(in.MXHost) {
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
